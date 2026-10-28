"""Run test/observer falsifiers and emit evidence that outcome-only runners omit.

Every witness runs in a
fresh child process.  A passing process is not HOLDS unless the named subject code
was executed; an observer is also not HOLDS unless its declared mechanism can see
the expected event class.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


CHILD = r'''
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

spec = json.loads(sys.argv[1])
subject_path = Path(spec["subject_path"]).resolve()
subject_filename = os.path.normcase(os.path.abspath(str(subject_path)))
subject_qualname = spec["subject_qualname"]
covered_lines = set()
audit_events = []

def profile(frame, event, arg):
    # Function-call coverage is enough to exclude a vacuous passing witness and
    # avoids tracing every executed Python line in pytest.
    if event != "call":
        return
    if frame.f_code.co_name != subject_qualname and getattr(frame.f_code, "co_qualname", "") != subject_qualname:
        return
    if os.path.normcase(os.path.abspath(frame.f_code.co_filename)) == subject_filename:
        covered_lines.add(frame.f_code.co_firstlineno)

def environment():
    return {
        "executable": sys.executable,
        "implementation": sys.implementation.name,
        "python": platform.python_version() if False else sys.version.split()[0],
        "platform": sys.platform,
        "cwd": str(Path.cwd()),
    }

sys.setprofile(profile)
exit_code = 0
error = None
try:
    if spec["kind"] == "test":
        import pytest
        basetemp = Path(os.environ.get("VSTD_WITNESS_BASETEMP", tempfile.gettempdir())) / "vstd-witness"
        basetemp.parent.mkdir(parents=True, exist_ok=True)
        exit_code = int(pytest.main([
            "-vv", "-s", "--durations=10", "--timeout=60",
            "-p", "no:fast_array_utils", "-p", "no:zarr",
            "-o", "tmp_path_retention_policy=failed",
            "--basetemp", str(basetemp), spec["node"],
        ]))
    else:
        module_spec = importlib.util.spec_from_file_location("q1_subject_runtime", subject_path)
        module = importlib.util.module_from_spec(module_spec)
        assert module_spec.loader is not None
        module_spec.loader.exec_module(module)
        function = getattr(module, subject_qualname)

        # Prepare resources before installing the observer, so setup cannot be
        # mistaken for subject behavior.
        temp_dir = Path(tempfile.mkdtemp(prefix="q1-observer-"))
        output_path = temp_dir / "output.txt"
        fd = None
        if spec["argument"] == "preopened-fd":
            fd = os.open(output_path, os.O_CREAT | os.O_WRONLY, 0o600)

        def audit(event, args):
            if event == "open":
                audit_events.append({"event": event, "class": "filesystem_open"})

        sys.addaudithook(audit)
        if spec["argument"] == "output-path":
            function(str(output_path))
        elif spec["argument"] == "preopened-fd":
            function(fd)
        else:
            raise ValueError("unknown observer argument " + repr(spec["argument"]))
        if fd is not None:
            os.close(fd)
except BaseException as exc:
    exit_code = 1
    error = type(exc).__name__ + ": " + str(exc)
finally:
    sys.setprofile(None)

print("Q1_CHILD_RECEIPT=" + json.dumps({
    "exit_code": exit_code,
    "error": error,
    "covered_lines": sorted(covered_lines),
    "audit_events": audit_events,
    "environment": environment(),
}, sort_keys=True))
raise SystemExit(exit_code)
'''


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def run_one(identifier: str, spec: dict) -> dict:
    child = subprocess.run(
        [sys.executable, "-c", CHILD, json.dumps(spec, sort_keys=True)],
        cwd=str(Path(spec["subject_path"]).resolve().parent),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    marker = "Q1_CHILD_RECEIPT="
    receipt_line = next((line for line in reversed(child.stdout.splitlines()) if line.startswith(marker)), None)
    child_receipt = json.loads(receipt_line[len(marker):]) if receipt_line else {
        "exit_code": child.returncode,
        "error": "missing child receipt",
        "covered_lines": [],
        "audit_events": [],
        "environment": {},
    }
    child_receipt["process_returncode"] = child.returncode
    child_receipt["stdout_sha256"] = hashlib.sha256(child.stdout.encode()).hexdigest()
    child_receipt["stderr_sha256"] = hashlib.sha256(child.stderr.encode()).hexdigest()

    producer = Path(spec["producer"]).resolve()
    subject = Path(spec["subject_path"]).resolve()
    independent = producer != subject
    covered = bool(child_receipt["covered_lines"])
    outcome_holds = child.returncode == 0 and child_receipt["exit_code"] == 0
    observable = set(spec.get("observable_event_classes", []))
    expected_class = spec.get("expected_event_class")
    capability = spec["kind"] != "observer" or expected_class in observable
    seen_classes = {event["class"] for event in child_receipt["audit_events"]}
    expectation_seen = spec["kind"] != "observer" or expected_class in seen_classes

    mutant = os.environ.get("Q1_WITNESS_MUTANT") == "trust-outcome"
    if mutant and outcome_holds:
        status = "HOLDS"
        rationale = "MUTANT trusted process outcome"
    elif not outcome_holds:
        status = "REFUTED"
        rationale = "witness process did not produce the expected successful outcome"
    elif not covered:
        status = "UNKNOWN"
        rationale = "process succeeded but named subject code was not covered"
    elif not capability:
        status = "UNKNOWN"
        rationale = "observer mechanism cannot see the expected event class"
    elif not expectation_seen:
        status = "REFUTED"
        rationale = "capable observer did not see the expected event class"
    else:
        status = "HOLDS"
        rationale = "outcome, subject coverage, and observer capability gates passed"

    return {
        "id": identifier,
        "kind": spec["kind"],
        "status": status,
        "rationale": rationale,
        "subject": {"path": str(subject), "qualname": spec["subject_qualname"], "covered": covered},
        "witness": {"producer": str(producer), "independent": independent},
        "observer": {
            "expected_event_class": expected_class,
            "observable_event_classes": sorted(observable),
            "seen_event_classes": sorted(seen_classes),
            "capable": capability,
        } if spec["kind"] == "observer" else None,
        "tier5_eligible": status == "HOLDS" and independent,
        "child": child_receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("specs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    specs = json.loads(args.specs.read_text(encoding="utf-8"))
    base = args.specs.resolve().parent
    repository = next((
        parent for parent in (base, *base.parents)
        if (parent / "pyproject.toml").is_file() and (parent / "src" / "verifier").is_dir()
    ), None)
    if repository is not None:
        os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, (
            str(repository), str(repository / "src"), str(base), os.environ.get("PYTHONPATH", ""),
        )))
    for spec in specs.values():
        for field in ("producer", "subject_path"):
            if spec[field] == "__runner__":
                spec[field] = str(Path(__file__).resolve())
            elif not Path(spec[field]).is_absolute():
                spec[field] = str((base / spec[field]).resolve())
        if spec["kind"] == "test":
            path, separator, selector = spec["node"].partition("::")
            if not Path(path).is_absolute():
                path = str((base / path).resolve())
            spec["node"] = path + (separator + selector if separator else "")
    result = {
        "schema": "vstd-witness-receipts/0.1",
        "mutant": os.environ.get("Q1_WITNESS_MUTANT"),
        "receipts": [run_one(identifier, specs[identifier]) for identifier in sorted(specs)],
    }
    args.output.write_bytes(canonical(result) + b"\n")
    for receipt in result["receipts"]:
        print(f"{receipt['id']}: {receipt['status']} independent={receipt['witness']['independent']} "
              f"tier5={receipt['tier5_eligible']} covered={receipt['subject']['covered']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
