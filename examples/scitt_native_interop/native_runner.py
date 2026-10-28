"""Opt-in native Supply Chain Integrity, Transparency, and Trust (SCITT) capture.

Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption
(COSE). Secure Hash Algorithm 256-bit (SHA-256) identifies bytes.
JavaScript Object Notation (JSON) records below contain observations, not verdicts.
The host explicitly selects the executable and its digest. No stored package can
authorize execution. Limits bound direct child duration and retained pipe bytes,
not hostile processes, descendants, filesystem races, or total runtime attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Any

from importlib.metadata import distribution, version


PROCESS_TIMEOUT_SECONDS = 20
CHANNEL_BYTE_LIMIT = 128 * 1024
MAX_INPUT_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
EXPECTED_SPECIMEN = {
    "signed_statement.cose": "3e6f2a928abc6162511d648305a91b7fa242803f4b607c4beb91a0d8ab8391b5",
    "receipt.cose": "700df05d3c99098f8dbabb0757bf24fbe46073aa3823e1f5612bb373f426cfea",
    "issuer_public.pem": "45b82e3528f834817db06868146f1a565badc739aeeeba864894778a7cd46db7",
    "log_public.pem": "e3272849658664b4b237ad6028d900584a7719c505af526a3c5a2b6e795f5d79",
    "transparent_statement.cose": "c75ff44dcc7b9630a05ad5c0040bc4c5dbb89651d47f345a18fdb4ddcb1bca7b",
    "vstd_scitt_payload.json": "35e2e6d2e15c983ba777fb91532bcad6680926905842ebcc3cc8540a7950d821",
    "artifact.txt": "39c442988b425a1e4cc7c6bb41d4fb35046dea61a5be3cdf39a582b054eae341",
}
PYTHON_DISTRIBUTION_PINS = {"scitt-cose": "0.2.2", "cbor2": "6.1.4", "cryptography": "50.0.0"}
PYTHON_SOURCE_PINS = {
    "scitt_cose/__init__.py": "9ac468cfd0ae08488ad1bf0dda944b0f097c0ba064d41628459c6f903da215e4",
    "scitt_cose/_status.py": "d498f541156fb76333520a0d24609bc0a0f8e40abf22cf451b8a3f3c1a546d66",
    "scitt_cose/cli.py": "73c89eee8294ba48a6e38555b1fa0011ffa6ba5be62a6f9e6f8f0cf33b89c315",
    "scitt_cose/cll.py": "35f65ba4871a90fe6224844577d2092f5d564cee005bf0b31b010f38e98c6ecc",
    "scitt_cose/cose_sign1.py": "571c06566de7f5c944006093661fda8dbf58d5213eda060d03d14f1a7a9a7778",
    "scitt_cose/merkle.py": "483b929d284af946253a1eb3e8b27137851807f83ac3605750cd44db3cd573ee",
    "scitt_cose/receipt.py": "3886d0a8e5feef3a5f9d37027177b614109da337c30c9d064a85f548e6c2bbd8",
    "scitt_cose/statement.py": "f7ca3d4f409216724d46dd0a28e3998f7ba7158a4c72a1006c17c7a90e591b5b",
    "scitt_cose/vectors.py": "e5cab3eac0b08a63ec3d0e9f2d8881d44b296aa6e647f198a7adeaf83f410fb6",
}


class NativeCaptureError(ValueError):
    """The explicit capture coordinate or retained input is inadmissible."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordinary(path: Path, *, directory: bool) -> os.stat_result:
    path = Path(os.path.abspath(path))
    for current in (*reversed(path.parents), path):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise NativeCaptureError("symbolic-link or reparse paths are not admissible")
        expected_directory = current != path or directory
        if not (stat.S_ISDIR(info.st_mode) if expected_directory else stat.S_ISREG(info.st_mode)):
            raise NativeCaptureError("path must have its ordinary file or directory type")
    return info


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def read_regular(path: Path, limit: int) -> bytes:
    """Bound reads, refuse aliases, and compare entry/open/end identities.

    Available no-follow flags and identity checks reduce races; privileged
    replacement and parent-directory races are not universally prevented.
    """
    if type(limit) is not int or limit < 0:
        raise NativeCaptureError("read limit must be a nonnegative integer")
    path = Path(os.path.abspath(path))
    before = _ordinary(path, directory=False)
    if before.st_size > limit:
        raise NativeCaptureError("file exceeds the explicit read bound")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise NativeCaptureError("file changed before its bounded read")
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > limit or _identity(os.fstat(descriptor)) != _identity(before):
            raise NativeCaptureError("file changed or exceeded its read bound")
    finally:
        os.close(descriptor)
    if _identity(_ordinary(path, directory=False)) != _identity(before):
        raise NativeCaptureError("file entry changed during the read")
    return bytes(chunks)


def build_corpus(specimen: dict[str, bytes]) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Reconstruct exactly twelve pinned cases without parsing or executing code."""
    if type(specimen) is not dict or set(specimen) != set(EXPECTED_SPECIMEN):
        raise NativeCaptureError("the exact seven retained specimen files are required")
    for name, expected in EXPECTED_SPECIMEN.items():
        data = specimen[name]
        if type(data) is not bytes or len(data) > MAX_INPUT_BYTES or sha256(data) != expected:
            raise NativeCaptureError(f"specimen identity mismatch: {name}")
    inputs = {"inputs/" + name: data for name, data in specimen.items()}
    statement, receipt = specimen["signed_statement.cose"], specimen["receipt.cose"]
    payload = specimen["vstd_scitt_payload.json"].rstrip(b"\n")
    if statement.count(payload) != 1:
        raise NativeCaptureError("pinned payload must occur once inside the pinned statement")
    offset = statement.index(payload)
    generated = {
        "statement-signature-bitflip.cose": statement[:-1] + bytes([statement[-1] ^ 1]),
        "receipt-signature-bitflip.cose": receipt[:-1] + bytes([receipt[-1] ^ 1]),
        "statement-payload-bitflip.cose": statement[:offset] + bytes([statement[offset] ^ 1]) + statement[offset + 1:],
        "statement-truncated.cose": statement[:-1],
        "receipt-truncated.cose": receipt[:-1],
    }
    inputs.update({"inputs/" + name: data for name, data in generated.items()})
    declarations = (
        ("positive-statement", "statement", "signed_statement.cose", "issuer_public.pem", None, True),
        ("positive-receipt", "receipt", "receipt.cose", "log_public.pem", "signed_statement.cose", True),
        ("statement-signature-bitflip", "statement", "statement-signature-bitflip.cose", "issuer_public.pem", None, False),
        ("receipt-signature-bitflip", "receipt", "receipt-signature-bitflip.cose", "log_public.pem", "signed_statement.cose", False),
        ("statement-payload-bitflip", "statement", "statement-payload-bitflip.cose", "issuer_public.pem", None, False),
        ("wrong-issuer-key", "statement", "signed_statement.cose", "log_public.pem", None, False),
        ("wrong-log-key", "receipt", "receipt.cose", "issuer_public.pem", "signed_statement.cose", False),
        ("wrong-leaf", "receipt", "receipt.cose", "log_public.pem", "statement-signature-bitflip.cose", False),
        ("statement-truncated", "statement", "statement-truncated.cose", "issuer_public.pem", None, False),
        ("receipt-truncated", "receipt", "receipt-truncated.cose", "log_public.pem", "signed_statement.cose", False),
        ("transparent-statement-signature", "statement", "transparent_statement.cose", "issuer_public.pem", None, True),
        ("transparent-leaf", "receipt", "receipt.cose", "log_public.pem", "transparent_statement.cose", False),
    )
    cases = [{"case_id": name, "facet": facet, "input_path": "inputs/" + source,
        "public_key_path": "inputs/" + key, "leaf_path": None if leaf is None else "inputs/" + leaf,
        "expected_accept": expected} for name, facet, source, key, leaf, expected in declarations]
    return {"schema_version": "SCITT-NATIVE-CORPUS-1", "cases": cases}, inputs


def _write_new(path: Path, data: bytes) -> None:
    _ordinary(path.parent, directory=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def _write_json(path: Path, value: Any) -> None:
    _write_new(path, (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8"))


def _run_process(name: str, arguments: list[str], cwd: Path, *, timeout: float = PROCESS_TIMEOUT_SECONDS,
                 output_limit: int = CHANNEL_BYTE_LIMIT) -> tuple[int | None, str | None, bytes, bytes]:
    """Observe binary pipes concurrently with finite queues and per-channel caps."""
    print(f"START {name}: direct process timeout={timeout}s channels<={output_limit} bytes", flush=True)
    started = time.monotonic()
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    events: queue.Queue = queue.Queue(maxsize=8)
    stopped = threading.Event()
    threads: list[threading.Thread] = []
    try:
        process = subprocess.Popen(arguments, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        print(f"END {name}: LAUNCH_ERROR", flush=True)
        return None, "LAUNCH_ERROR", b"", b""

    def pump(channel: str, pipe: Any) -> None:
        try:
            while not stopped.is_set():
                chunk = pipe.read(4096)
                event = (channel, chunk if chunk else None)
                while not stopped.is_set():
                    try:
                        events.put(event, timeout=0.05)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    break
        except OSError:
            while not stopped.is_set():
                try:
                    events.put((channel, False), timeout=0.05)
                    break
                except queue.Full:
                    continue

    closed: set[str] = set()
    reason = None
    last_progress = started
    try:
        for channel in outputs:
            threads.append(threading.Thread(target=pump, args=(channel, getattr(process, channel)), daemon=True))
        for thread in threads:
            thread.start()
        while len(closed) < 2 or process.poll() is None:
            now = time.monotonic()
            if now - started >= timeout:
                reason = "TIMEOUT"
                break
            if now - last_progress >= 1:
                print(f"PROGRESS {name}: elapsed={now - started:.1f}s stdout={len(outputs['stdout'])} stderr={len(outputs['stderr'])}", flush=True)
                last_progress = now
            try:
                channel, chunk = events.get(timeout=min(0.05, max(0.001, timeout - (now - started))))
            except queue.Empty:
                continue
            if chunk is None:
                closed.add(channel)
                continue
            if chunk is False:
                reason = "LAUNCH_ERROR"
                break
            remaining = output_limit - len(outputs[channel])
            retained = chunk[:remaining]
            outputs[channel].extend(retained)
            if retained:
                print(f"[{name}/{channel}] {retained!r}", flush=True)
            if len(chunk) > remaining:
                reason = "OUTPUT_LIMIT"
                break
    except BaseException:
        reason = "CANCELLED"
        raise
    finally:
        stopped.set()
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            code, reason = None, "TIMEOUT"
        except OSError:
            code, reason = None, "LAUNCH_ERROR"
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=0.1)
        for index, channel in enumerate(outputs):
            if index >= len(threads) or not threads[index].is_alive():
                getattr(process, channel).close()
        if reason == "CANCELLED":
            print(f"END {name}: observer cancelled; direct-child cleanup attempted", flush=True)
    print(f"END {name}: exit={code} stop={reason} elapsed={time.monotonic() - started:.3f}s", flush=True)
    return code, reason, bytes(outputs["stdout"]), bytes(outputs["stderr"])


def _python_inventory() -> dict[str, Any]:
    """Run only in the current interpreter's isolated preflight child."""
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise NativeCaptureError("Python preflight must use isolated no-bytecode mode")
    versions = {
        "scitt-cose": version("scitt-cose"),
        "cbor2": version("cbor2"),
        "cryptography": version("cryptography"),
    }
    if versions != PYTHON_DISTRIBUTION_PINS:
        raise NativeCaptureError("Python distribution version mismatch")
    scitt_distribution = distribution("scitt-cose")
    scitt_files = tuple(scitt_distribution.files or ())
    inventory = {str(item).replace("\\", "/") for item in scitt_files if str(item).replace("\\", "/").startswith("scitt_cose/") and str(item).endswith(".py")}
    if inventory != set(PYTHON_SOURCE_PINS):
        raise NativeCaptureError("Python source inventory differs from fixed pins")
    sources = {}
    for name in sorted(inventory):
        sources[name] = sha256(
            read_regular(
                Path(scitt_distribution.locate_file(name)), MAX_SOURCE_BYTES
            )
        )
    if sources != PYTHON_SOURCE_PINS:
        raise NativeCaptureError("Python source digest mismatch")
    for distribution_name, module_name in (("scitt-cose", "scitt_cose"), ("cbor2", "cbor2"), ("cryptography", "cryptography")):
        dist = distribution(distribution_name)
        dist_files = tuple(dist.files or ())
        spec = importlib.util.find_spec(module_name)
        if spec is None or spec.origin is None:
            raise NativeCaptureError("Python native import location is unavailable")
        origin = Path(os.path.abspath(spec.origin))
        _ordinary(origin, directory=False)
        supplied = False
        for item in dist_files:
            if Path(os.path.abspath(dist.locate_file(item))) == origin:
                supplied = True
                break
        if not supplied:
            raise NativeCaptureError("Python import does not match the installed distribution")
    return {"python_version": platform.python_version(), "python_executable_sha256": sha256(read_regular(Path(sys.executable), MAX_BINARY_BYTES)),
        "python_distributions": versions, "python_source_sha256": sources}


def _python_snapshot(name: str, cwd: Path) -> dict[str, Any] | None:
    code, reason, stdout, stderr = _run_process(name, [sys.executable, "-I", "-B", "-u", str(Path(__file__).absolute()), "--python-preflight"], cwd)
    if code != 0 or reason is not None or stderr:
        return None
    try:
        value = json.loads(stdout)
    except (UnicodeError, ValueError):
        return None
    if type(value) is not dict or set(value) != {"python_version", "python_executable_sha256", "python_distributions", "python_source_sha256"}:
        return None
    if value["python_distributions"] != PYTHON_DISTRIBUTION_PINS or value["python_source_sha256"] != PYTHON_SOURCE_PINS:
        return None
    return value


def _arguments(case: dict[str, Any], implementation: str, go_checker: Path, inputs: dict[str, bytes]) -> list[str]:
    if implementation == "python":
        prefix = [sys.executable, "-I", "-B", "-u", "-m", "scitt_cose.cli", "--json"]
        flags = ["--statement", case["input_path"], "--statement-pubkey", case["public_key_path"]] if case["facet"] == "statement" else ["--receipt", case["input_path"], "--receipt-log-pubkey", case["public_key_path"], "--leaf-entry-hex", inputs[case["leaf_path"]].hex()]
    else:
        prefix = [str(go_checker)]
        flags = ["--statement", case["input_path"], "--pubkey", case["public_key_path"], "--alg", "EdDSA"] if case["facet"] == "statement" else ["--receipt", case["input_path"], "--log-pubkey", case["public_key_path"], "--leaf-entry-hex", inputs[case["leaf_path"]].hex()]
    return prefix + flags


def capture_comparison(go_checker: Path, expected_go_sha256: str, *, specimen_dir: Path, output_dir: Path) -> None:
    """Capture a host-authorized fixed comparison into a new exclusive directory."""
    if type(expected_go_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_go_sha256) is None:
        raise NativeCaptureError("Go digest must be canonical lowercase SHA-256")
    go_checker, specimen_dir, output_dir = (Path(os.path.abspath(item)) for item in (go_checker, specimen_dir, output_dir))
    if sha256(read_regular(go_checker, MAX_BINARY_BYTES)) != expected_go_sha256:
        raise NativeCaptureError("Go executable does not match the host-selected digest")
    executable_digest = sha256(read_regular(Path(sys.executable), MAX_BINARY_BYTES))
    runner_digest = sha256(read_regular(Path(__file__), MAX_SOURCE_BYTES))
    _ordinary(specimen_dir, directory=True)
    generated = specimen_dir / "generated"
    nested = generated.exists()
    if nested:
        _ordinary(generated, directory=True)
    specimen = {name: read_regular((specimen_dir / name if name == "artifact.txt" or not nested else generated / name), MAX_INPUT_BYTES) for name in EXPECTED_SPECIMEN}
    corpus, inputs = build_corpus(specimen)
    _ordinary(output_dir.parent, directory=True)
    os.mkdir(output_dir)  # Existing files, directories, and dangling aliases refuse.
    os.mkdir(output_dir / "inputs")
    os.mkdir(output_dir / "outputs")
    for relative, content in inputs.items():
        _write_new(output_dir / relative, content)
    _write_json(output_dir / "corpus.json", corpus)
    initial = _python_snapshot("initial-python-preflight", output_dir)
    unchanged = initial is not None and initial["python_executable_sha256"] == executable_digest
    observations = []

    def identity_check(name: str) -> bool:
        try:
            if sha256(read_regular(go_checker, MAX_BINARY_BYTES)) != expected_go_sha256 or sha256(read_regular(Path(__file__), MAX_SOURCE_BYTES)) != runner_digest:
                return False
            if any(read_regular(output_dir / relative, MAX_INPUT_BYTES) != content for relative, content in inputs.items()):
                return False
            snapshot = _python_snapshot(name, output_dir)
            return snapshot is not None and snapshot == initial
        except (OSError, ValueError):
            return False

    for case in corpus["cases"]:
        for implementation in ("python", "go"):
            name = case["case_id"] + "-" + implementation
            before = identity_check(name + "-before")
            if before:
                code, stop, stdout, stderr = _run_process(name, _arguments(case, implementation, go_checker, inputs), output_dir)
            else:
                print(f"START {name}: identity preflight refused; no native invocation", flush=True)
                code, stop, stdout, stderr = None, "LAUNCH_ERROR", b"", b""
                print(f"END {name}: LAUNCH_ERROR", flush=True)
            after = identity_check(name + "-after")
            unchanged = unchanged and before and after
            if not after:
                stop = "LAUNCH_ERROR"  # Operational identity failure, never semantic rejection.
            stdout_path, stderr_path = f"outputs/{name}.stdout", f"outputs/{name}.stderr"
            _write_new(output_dir / stdout_path, stdout)
            _write_new(output_dir / stderr_path, stderr)
            observations.append({"case_id": case["case_id"], "implementation": implementation,
                "exit_code": code, "stop_reason": stop, "stdout_path": stdout_path, "stderr_path": stderr_path,
                "stdout_sha256": sha256(stdout), "stderr_sha256": sha256(stderr)})
    _write_json(output_dir / "observations.json", {"schema_version": "SCITT-NATIVE-OBSERVATIONS-1", "observations": observations})
    _write_json(output_dir / "runtime.json", {"schema_version": "SCITT-NATIVE-RUNTIME-1",
        "platform_system": platform.system(), "platform_machine": platform.machine(),
        "python_version": platform.python_version() if initial is None else initial["python_version"],
        "python_executable_sha256": executable_digest,
        "python_distributions": {} if initial is None else initial["python_distributions"],
        "python_source_sha256": {} if initial is None else initial["python_source_sha256"],
        "go_checker_sha256": expected_go_sha256, "source_state_unchanged": unchanged, "runner_sha256": runner_digest})


def main(argv: list[str] | None = None) -> int:
    """Expose only host-supplied capture inputs; stored records grant no authority."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--python-preflight"]:
        try:
            print(json.dumps(_python_inventory(), sort_keys=True), flush=True)
        except (OSError, ValueError, ImportError):
            print("Python runtime preflight failed.", file=sys.stderr, flush=True)
            return 1
        return 0
    parser = argparse.ArgumentParser(description="Capture twelve fixed native comparisons using explicitly host-selected executables.")
    parser.add_argument("--go-checker", type=Path, required=True)
    parser.add_argument("--expected-go-sha256", required=True, help="Host-selected lowercase 64-character SHA-256 digest.")
    parser.add_argument("--specimen-dir", type=Path, default=Path(__file__).absolute().parent.parent / "scitt_interop")
    parser.add_argument("--output-dir", type=Path, required=True, help="Absent directory with an existing ordinary parent.")
    args = parser.parse_args(arguments)
    capture_comparison(args.go_checker, args.expected_go_sha256,
                       specimen_dir=args.specimen_dir, output_dir=args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
