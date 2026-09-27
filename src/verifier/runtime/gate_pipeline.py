"""Local Verifier Standard (VSTD) command-line interface (CLI) automation.

JavaScript Object Notation (JSON) receipts bind selected bytes with Secure Hash
Algorithm 256-bit (SHA-256); signal kill (SIGKILL). They establish no numbered-profile conformance,
authenticity, sandboxing, complete dependency closure, or domain correctness.
Deadlines use seconds; output limits use bytes. Commands are explicit authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable

SCHEMA = "verifier-gate-pipeline-1"
RECEIPT = "verifier-gate-pipeline-receipt-1"
LIMIT = 16 * 1024 * 1024
BOUNDARY = "Local command exits and selected input integrity only; no sandbox, authenticity, domain correctness or numbered-profile certification. Inherited environment and unselected dependencies are not bound."


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError("regular non-linked file required")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("file byte bound exceeded")
    return raw


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(_read(path), object_pairs_hook=_pairs)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def _keys(value: Any, keys: str) -> None:
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError("unknown or missing fields")


def _relative(root: Path, name: Any) -> Path:
    if type(name) is not str or not name or "\\" in name or ":" in name:
        raise ValueError("relative portable path required")
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("escaping path")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise ValueError("linked paths unsupported")
    result = current.resolve()
    if result != root and root not in result.parents:
        raise ValueError("escaping path")
    return result


def _seconds(value: Any) -> None:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.05 <= value <= 3600:
        raise ValueError("deadline must be finite, 0.05 through 3600 seconds")


def _manifest(path: Path) -> tuple[dict[str, Any], Path, list[str]]:
    value = _load(path)
    _keys(value, "schema_version root inputs steps overall_timeout_seconds max_output_bytes")
    if value["schema_version"] != SCHEMA:
        raise ValueError("unsupported pipeline schema")
    root = _relative(path.resolve().parent, value["root"])
    if not root.is_dir():
        raise ValueError("root is not a directory")
    _seconds(value["overall_timeout_seconds"])
    if type(value["max_output_bytes"]) is not int or not 1 <= value["max_output_bytes"] <= 1024 * 1024:
        raise ValueError("output byte bound must be 1 through 1048576")
    if type(value["inputs"]) is not list or not 1 <= len(value["inputs"]) <= 128:
        raise ValueError("nonempty selected input scope required")
    for name in value["inputs"]:
        _relative(root, name)
    if type(value["steps"]) is not list or not 1 <= len(value["steps"]) <= 64:
        raise ValueError("one through 64 steps required")
    steps: dict[str, dict[str, Any]] = {}
    for step in value["steps"]:
        if type(step) is not dict:
            raise ValueError("step object required")
        _keys(step, "id argv needs timeout_seconds" + (" result_contract" if "result_contract" in step else ""))
        if "result_contract" in step and step["result_contract"] != "vstd-verdict":
            raise ValueError("unsupported result contract")
        name = step["id"]
        if type(name) is not str or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", name) or name in steps:
            raise ValueError("invalid or duplicate step identifier")
        argv = step["argv"]
        if type(argv) is not list or not 1 <= len(argv) <= 128 or any(type(arg) is not str or not arg or "\x00" in arg or len(arg) > 8192 for arg in argv):
            raise ValueError("explicit nonempty argument array required")
        if type(step["needs"]) is not list or any(type(item) is not str for item in step["needs"]) or len(set(step["needs"])) != len(step["needs"]):
            raise ValueError("unique dependency identifiers required")
        _seconds(step["timeout_seconds"])
        steps[name] = step
    order: list[str] = []
    while len(order) < len(steps):
        ready = [name for name, step in steps.items() if name not in order and all(dep in order for dep in step["needs"])]
        if not ready:
            raise ValueError("cycle or unknown dependency")
        order.extend(ready)
    return value, root, order


def _inventory(root: Path, inputs: list[str], excluded: Path | None) -> list[dict[str, Any]]:
    files: dict[str, Path] = {}
    pending = [_relative(root, name) for name in inputs]
    visited = 0
    while pending:
        path = pending.pop()
        visited += 1
        if visited > 4096:
            raise ValueError("input traversal bound exceeded")
        _relative(root, path.relative_to(root).as_posix())
        if path == excluded:
            continue
        if path.is_dir():
            pending.extend(path.iterdir())
        elif path.is_file():
            files[path.relative_to(root).as_posix()] = path
        else:
            raise ValueError("missing or unsupported input")
    if not files or len(files) > 1024:
        raise ValueError("selected scope must contain 1 through 1024 regular files")
    records = []
    total = 0
    for name, path in sorted(files.items()):
        raw = _read(path)
        total += len(raw)
        if total > LIMIT:
            raise ValueError("input byte bound exceeded")
        records.append({"path": name, "size_bytes": len(raw), "digest": _digest(raw)})
    return records


def _executables(value: dict[str, Any], root: Path) -> list[dict[str, str]]:
    records = []
    for step in value["steps"]:
        name = step["argv"][0]
        found = str((root / name).resolve()) if "/" in name or "\\" in name else shutil.which(name)
        if not found or not Path(found).is_file() or Path(found).suffix.lower() in {".bat", ".cmd"}:
            raise ValueError("executable unavailable or implicit shell script")
        found = str(Path(found).resolve())
        records.append({"id": step["id"], "path": found, "digest": _digest(_read(Path(found)))})
    return records


def plan_pipeline(manifest_path: str | Path) -> dict[str, Any]:
    """Validate a plan without starting commands. This is not a safety approval."""
    path = Path(manifest_path)
    value, root, order = _manifest(path)
    return {"status": "PASS", "claim_boundary": BOUNDARY, "manifest_digest": _digest(_read(path)),
            "order": order, "inputs": _inventory(root, value["inputs"], None), "executables": _executables(value, root)}


def _windows_job(process: subprocess.Popen[bytes]) -> Callable[[], None]:
    """Assign a suspended child before resuming it; descendants inherit the job."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    handle = int(process._handle)  # CPython's Windows subprocess handle.
    if not job or not kernel.AssignProcessToJobObject(job, handle):
        if job:
            kernel.CloseHandle(job)
        raise OSError("owned process job assignment failed")
    native = ctypes.WinDLL("ntdll")
    native.NtResumeProcess.argtypes = [wintypes.HANDLE]
    if native.NtResumeProcess(handle) != 0:
        kernel.TerminateJobObject(job, 1)
        kernel.CloseHandle(job)
        raise OSError("owned process resume failed")

    def stop() -> None:
        try:
            if not kernel.TerminateJobObject(job, 1):
                raise OSError("owned job cleanup failed")
            deadline = time.monotonic() + 5
            accounting = ctypes.create_string_buffer(48)
            while True:
                if not kernel.QueryInformationJobObject(job, 1, accounting, 48, None):
                    raise OSError("owned job exit unavailable")
                if struct.unpack_from("I", accounting.raw, 40)[0] == 0:
                    break
                if time.monotonic() >= deadline:
                    raise OSError("owned job exit deadline exceeded")
                time.sleep(.01)
        finally:
            kernel.CloseHandle(job)
    return stop


def _command(argv: list[str], root: Path, deadline: float, maximum: int,
             progress: Callable[[str], None]) -> dict[str, Any]:
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    exceeded = threading.Event()
    read_failed = threading.Event()
    process: subprocess.Popen[bytes] | None = None
    stop: Callable[[], None] | None = None
    readers: list[threading.Thread] = []
    status, code, cleanup = "ERROR", None, "NOT_STARTED"

    def read(stream: Any, target: bytearray, channel: str) -> None:
        try:
            while True:
                chunk = stream.read1(4096)
                if not chunk:
                    return
                with lock:
                    left = maximum - sum(len(part) for part in buffers)
                    retained = chunk[:left]
                    target.extend(retained)
                    if len(chunk) > left:
                        exceeded.set()
                if retained:
                    progress(channel + ": " + retained.decode("utf-8", "replace"))
        except (OSError, ValueError):
            read_failed.set()
        finally:
            stream.close()
    try:
        process = subprocess.Popen(argv, cwd=root, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=os.name != "nt",
                                   creationflags=0x00000004 | 0x08000000 if os.name == "nt" else 0)
        if os.name == "nt":
            stop = _windows_job(process)
        else:
            def stop_group() -> None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            stop = stop_group
        for stream, target, channel in zip((process.stdout, process.stderr), buffers, ("stdout", "stderr")):
            reader = threading.Thread(target=read, args=(stream, target, channel), daemon=True)
            reader.start()
            readers.append(reader)
        next_update = time.monotonic() + 5
        while process.poll() is None:
            now = time.monotonic()
            if exceeded.is_set():
                status = "OUTPUT_LIMIT"
                break
            if now >= deadline:
                status = "TIMEOUT"
                break
            if now >= next_update:
                progress("running (deadline enforced)")
                next_update = now + 5
            time.sleep(min(0.02, max(0, deadline - now)))
        else:
            status = "PASS" if process.returncode == 0 else "FAIL"
    except (OSError, ValueError):
        status = "ERROR"
    finally:
        if process is not None:
            try:
                if stop is not None:
                    stop()
                else:
                    process.kill()
                code = process.wait(timeout=5)
                for reader in readers:
                    reader.join(timeout=2)
                cleanup = ("OWNED_TREE_TERMINATED" if os.name == "nt" else "OWNED_GROUP_SIGNALLED") if not any(reader.is_alive() for reader in readers) else "UNKNOWN"
            except (OSError, subprocess.TimeoutExpired):
                cleanup = "UNKNOWN"
    if exceeded.is_set():
        status = "OUTPUT_LIMIT"
    if cleanup == "UNKNOWN" or read_failed.is_set():
        status = "ERROR"
    return {"status": status, "exit_code": code, "stdout": buffers[0].decode("utf-8", "replace"),
            "stderr": buffers[1].decode("utf-8", "replace"), "cleanup": cleanup}


def _verdict(step: dict[str, Any], result: dict[str, Any]) -> str:
    """Interpret an explicitly selected producer protocol, without proving its claim."""
    if "result_contract" not in step:
        return "PASS" if result["exit_code"] == 0 else "FAIL"
    try:
        output = json.loads(result["stdout"], object_pairs_hook=_pairs)
        if type(output) is not dict:
            raise ValueError("result object required")
        _canonical(output)  # Reject non-finite constants as well as duplicate keys.
        if output.get("schema_version") in {"verifier-domain-certification-1", "verifier-grounded-certification-1"}:
            output = output["result"]
        status = output["status"]
        if type(status) is not str or status not in {"PASS", "FAIL", "UNKNOWN", "REJECTED"}:
            raise ValueError("unsupported reported verdict")
        if result["exit_code"] != {"PASS": 0, "FAIL": 1, "UNKNOWN": 2, "REJECTED": 1}[status]:
            raise ValueError("reported verdict contradicts process exit")
        return "FAIL" if status == "REJECTED" else status
    except (ValueError, TypeError, KeyError, RecursionError):
        return "ERROR"


def _aggregate(steps: list[dict[str, Any]], results: list[dict[str, Any]], unchanged: bool) -> str:
    """Failure dominates uncertainty; a blocked independent check remains a failure."""
    if not unchanged or any(row["status"] in {"FAIL", "ERROR", "TIMEOUT", "OUTPUT_LIMIT"} for row in results):
        return "FAIL"
    statuses = {row["id"]: row["status"] for row in results}
    for row in results:
        if row["status"] == "BLOCKED":
            needs = next(step["needs"] for step in steps if step["id"] == row["id"])
            if not any(statuses[dependency] != "PASS" for dependency in needs):
                return "FAIL"
    if any(row["status"] == "UNKNOWN" for row in results):
        return "UNKNOWN"
    return "PASS" if all(row["status"] == "PASS" for row in results) else "FAIL"


def _mechanism() -> str:
    return _digest(Path(__file__).read_bytes())


def run_pipeline(manifest_path: str | Path, output: str | Path, *,
                 progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Execute explicitly authorized commands, retaining failure and blocked steps."""
    emit = progress or (lambda message: print(message, file=sys.stderr, flush=True))
    path = Path(manifest_path).resolve()
    value, root, order = _manifest(path)
    destination = Path(output).absolute()
    # Outputs may be outside selected inputs, but never alias the manifest or exist.
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("receipt destination must be new with existing parent")
    if destination.parent.resolve() != destination.parent:
        raise ValueError("linked receipt parent unsupported")
    initial = _inventory(root, value["inputs"], destination)
    executables = _executables(value, root)
    manifest_digest = _digest(_read(path))
    mechanism_digest = _mechanism()
    deadline = time.monotonic() + value["overall_timeout_seconds"]
    results: list[dict[str, Any]] = []
    passed: set[str] = set()
    remaining = value["max_output_bytes"]
    with destination.open("xb") as stream:
        for name in order:
            step = next(item for item in value["steps"] if item["id"] == name)
            emit(name + ": START")
            if any(dep not in passed for dep in step["needs"]) or time.monotonic() >= deadline or remaining <= 0:
                result = {"status": "BLOCKED", "exit_code": None, "stdout": "", "stderr": "", "cleanup": "NOT_STARTED"}
            else:
                executable = next(item for item in executables if item["id"] == name)
                result = _command([executable["path"], *step["argv"][1:]], root,
                                  min(deadline, time.monotonic() + step["timeout_seconds"]), remaining,
                                  lambda message: emit(name + ": " + message))
                if result["status"] in {"PASS", "FAIL"}:
                    result["status"] = _verdict(step, result)
            result["id"] = name
            results.append(result)
            remaining -= len(result["stdout"].encode()) + len(result["stderr"].encode())
            if result["status"] == "PASS":
                passed.add(name)
            emit(name + ": " + result["status"])
        try:
            final = _inventory(root, value["inputs"], destination)
            unchanged = initial == final and manifest_digest == _digest(_read(path)) and executables == _executables(value, root) and mechanism_digest == _mechanism()
        except (OSError, ValueError):
            final, unchanged = [], False
        receipt = {"schema_version": RECEIPT, "claim_boundary": BOUNDARY,
                   "manifest": value, "manifest_digest": manifest_digest,
                   "manifest_path": os.path.relpath(path, destination.parent).replace("\\", "/"),
                   "mechanism_digest": mechanism_digest, "python": sys.version, "platform": sys.platform,
                   "inputs": initial, "final_inputs": final, "executables": executables,
                   "inputs_unchanged": unchanged, "steps": results,
                   "status": _aggregate(value["steps"], results, unchanged)}
        receipt["receipt_digest"] = _digest(_canonical(receipt))
        stream.write(_canonical(receipt) + b"\n")
    return receipt


def check_pipeline(receipt_path: str | Path, *, manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Rehash receipt/current context, never execute commands or attest authorship."""
    try:
        receipt_file = Path(receipt_path).resolve()
        receipt = _load(receipt_file)
        _keys(receipt, "schema_version claim_boundary manifest manifest_digest manifest_path mechanism_digest python platform inputs final_inputs executables inputs_unchanged steps status receipt_digest")
        digest = receipt.pop("receipt_digest")
        if receipt["schema_version"] != RECEIPT or digest != _digest(_canonical(receipt)):
            raise ValueError("receipt integrity mismatch")
        # Receipt-carried paths are data, never authority to read outside its directory.
        path = Path(manifest_path) if manifest_path is not None else _relative(receipt_file.parent, receipt["manifest_path"])
        value, root, order = _manifest(path)
        if receipt["manifest"] != value or receipt["manifest_digest"] != _digest(_read(path)):
            raise ValueError("manifest changed")
        if receipt["mechanism_digest"] != _mechanism() or receipt["python"] != sys.version or receipt["platform"] != sys.platform:
            raise ValueError("mechanism or interpreter context changed")
        if receipt["inputs"] != _inventory(root, value["inputs"], receipt_file) or receipt["executables"] != _executables(value, root):
            raise ValueError("input or executable context changed")
        if [step["id"] for step in receipt["steps"]] != order:
            raise ValueError("step order mismatch")
        if type(receipt["inputs_unchanged"]) is not bool:
            raise ValueError("invalid input-change observation")
        passed: set[str] = set()
        observed_output = 0
        for step in receipt["steps"]:
            _keys(step, "id status exit_code stdout stderr cleanup")
            if type(step["stdout"]) is not str or type(step["stderr"]) is not str or (step["exit_code"] is not None and type(step["exit_code"]) is not int):
                raise ValueError("invalid step result types")
            # A replacement character can represent one invalid original byte.
            # Check the minimum possible original byte count, not a false exact
            # reconstruction of the lossy text representation.
            observed_output += sum(len(text.encode()) - 2 * text.count("\ufffd") for text in (step["stdout"], step["stderr"]))
            if observed_output > value["max_output_bytes"]:
                raise ValueError("retained output exceeds decoding bound")
            if step["status"] not in {"PASS", "FAIL", "UNKNOWN", "ERROR", "TIMEOUT", "OUTPUT_LIMIT", "BLOCKED"}:
                raise ValueError("invalid step status")
            if step["status"] == "BLOCKED" and (step["exit_code"] is not None or step["stdout"] or step["stderr"] or step["cleanup"] != "NOT_STARTED"):
                raise ValueError("blocked step claims execution")
            cleanup = "OWNED_TREE_TERMINATED" if receipt["platform"] == "win32" else "OWNED_GROUP_SIGNALLED"
            declared = next(item for item in value["steps"] if item["id"] == step["id"])
            if step["status"] in {"PASS", "FAIL", "UNKNOWN"}:
                if step["exit_code"] is None or step["cleanup"] != cleanup or step["status"] != _verdict(declared, step):
                    raise ValueError("command verdict or exit is inconsistent")
                if any(dep not in passed for dep in declared["needs"]):
                    raise ValueError("executed step has an unmet dependency")
            if step["status"] == "PASS":
                passed.add(step["id"])
        expected = _aggregate(value["steps"], receipt["steps"],
                              receipt["inputs_unchanged"] is True and receipt["inputs"] == receipt["final_inputs"])
        if receipt["status"] != expected or receipt["claim_boundary"] != BOUNDARY:
            raise ValueError("aggregate mismatch")
        return {"status": receipt["status"], "integrity_status": "PASS", "run_status": receipt["status"], "claim_boundary": BOUNDARY, "receipt_digest": digest}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return {"status": "FAIL", "reason": "receipt integrity or current context unavailable/mismatched; supply --manifest when relocated", "claim_boundary": BOUNDARY}


def init_pipeline(path: str | Path = "gate_pipeline.json", *, inputs: list[str] | None = None,
                  preset: str = "project") -> dict[str, Any]:
    """Write real selected-source checks exclusively; never run or install them."""
    target = Path(path)
    selected = ["."] if inputs is None else inputs
    if preset not in {"project", "python"} or not selected or len(selected) > 21:
        raise ValueError("project/python preset and one through 21 inputs required")
    root = target.resolve().parent
    for name in selected:
        _relative(root, name)
    steps = []
    for index, name in enumerate(selected):
        commands = ["paths", "boundary"]
        if preset == "python" and (_relative(root, name).is_dir() or Path(name).suffix == ".py"):
            commands.append("ast")
        for command in commands:
            steps.append({"id": f"{command}_{index}",
                          "argv": ["python", "-B", "-m", "verifier", "gate", command, name, "--json"],
                          "needs": [], "timeout_seconds": 30, "result_contract": "vstd-verdict"})
    value = {"schema_version": SCHEMA, "root": ".", "inputs": selected,
             "overall_timeout_seconds": 300, "max_output_bytes": 1048576, "steps": steps}
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
    return {"status": "PASS", "manifest": str(target), "claim_boundary": BOUNDARY}


def add_pipeline_parsers(subparsers: Any) -> None:
    for name in ("init", "plan", "run", "check"):
        parser = subparsers.add_parser(name, help=name + " a local bounded command pipeline")
        parser.add_argument("path", nargs="?" if name == "init" else None, default="gate_pipeline.json" if name == "init" else None)
        parser.add_argument("--json", action="store_true")
        if name == "init":
            parser.add_argument("--input", action="append", dest="inputs", help="Selected relative project input; repeat to narrow scope (default: .).")
            parser.add_argument("--preset", choices=("project", "python"), default="project",
                                help="Project paths/boundary checks, plus Python source-pattern checks when selected.")
        if name == "run":
            parser.add_argument("--output", required=True)
        if name == "check":
            parser.add_argument("--manifest")
        parser.set_defaults(pipeline_action=name)


def handle_pipeline_command(args: argparse.Namespace) -> int:
    try:
        action = args.pipeline_action
        if action == "init":
            result = init_pipeline(args.path, inputs=args.inputs, preset=args.preset)
        elif action == "plan":
            result = plan_pipeline(args.path)
        elif action == "run":
            result = run_pipeline(args.path, args.output)
        else:
            result = check_pipeline(args.path, manifest_path=args.manifest)
    except (OSError, ValueError, RecursionError) as error:
        result = {"status": "FAIL", "reason": str(error), "claim_boundary": BOUNDARY}
    print(json.dumps(result, sort_keys=True) if args.json else result["status"])
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
