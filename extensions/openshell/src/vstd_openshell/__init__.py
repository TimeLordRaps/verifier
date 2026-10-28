"""Optional NVIDIA OpenShell transport; no object obligation is discharged.

The command-line interface (CLI) is pinned to 0.1.3. JavaScript Object Notation
(JSON) carries policy and observations. Secure Hash Algorithm 256-bit (SHA-256)
binds bytes, not their truth. Only newly created, ownership-labelled sandboxes
are mutated. This adapter never installs software, approves network rules,
attaches credentials, forwards ports, mounts the host, or falls back locally.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any
import uuid

VERSION = "0.1.3"
LIMIT = 1024 * 1024
CONTROL_NAMES = frozenset({"workspace-read-write", "nonroot", "denied-file-exists-world-readable",
                           "filesystem-denial", "direct-network-denial"})
POLICY = {"version": 1, "filesystem_policy": {"include_workdir": False,
    "read_only": ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/alternatives", "/proc"],
    "read_write": ["/sandbox", "/tmp", "/dev/null", "/dev/urandom"]},
    "landlock": {"compatibility": "hard_requirement"},
    "process": {"run_as_user": "1000", "run_as_group": "1000"}, "network_policies": {}}

# These controls run before subject code, in the same sandbox generation.
# A refused connection or missing file is NOT counted as a policy denial.
PROBE = '''import errno, json, os, socket, stat, tempfile
checks = {}
with tempfile.NamedTemporaryFile(dir="/sandbox", mode="w+") as f:
    f.write("allowed-control"); f.flush(); f.seek(0)
    checks["workspace-read-write"] = f.read() == "allowed-control"
checks["nonroot"] = os.getuid() == 1000 and os.getgid() == 1000
st = os.stat("/etc/hostname")
checks["denied-file-exists-world-readable"] = stat.S_ISREG(st.st_mode) and bool(st.st_mode & stat.S_IROTH)
try:
    open("/etc/hostname").read()
    checks["filesystem-denial"] = False
except OSError as e:
    checks["filesystem-denial"] = e.errno in (errno.EACCES, errno.EPERM)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
    s.connect(("192.0.2.1", 9))
    checks["direct-network-denial"] = False
except OSError as e:
    checks["direct-network-denial"] = e.errno in (errno.EACCES, errno.EPERM)
finally:
    if "s" in locals(): s.close()
print(json.dumps(checks, sort_keys=True))
raise SystemExit(0 if all(checks.values()) else 1)
'''
SOURCE_CHECK = '''import hashlib, json, pathlib, sys
expected = json.loads(sys.argv[1])
actual = {p: hashlib.sha256((pathlib.Path("/sandbox/source") / p).read_bytes()).hexdigest() for p in expected}
print(json.dumps(actual, sort_keys=True))
raise SystemExit(0 if actual == expected else 1)
'''


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("RUNNER_SANDBOX_DUPLICATE_KEY")
        result[key] = value
    return result


def _json(data: str) -> Any:
    return json.loads(data, object_pairs_hook=_unique)


def _config(path: str, profile: dict[str, Any]) -> dict[str, Any]:
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("RUNNER_SANDBOX_CONFIG_CAPACITY")
    config = _json(raw.decode("utf-8"))
    required = {"schema_version", "gateway", "workspace", "image", "cpu", "memory", "reason", "lifecycle"}
    if type(config) is not dict or set(config) - required - {"bindings"} or required - set(config):
        raise ValueError("RUNNER_SANDBOX_CONFIG_FIELDS")
    if config["schema_version"] != "verifier-openshell-config-1":
        raise ValueError("RUNNER_SANDBOX_CONFIG_VERSION")
    for field in ("gateway", "workspace"):
        if type(config[field]) is not str or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", config[field]):
            raise ValueError("RUNNER_SANDBOX_TARGET_INVALID")
    if not isinstance(config["image"], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}", config["image"]):
        raise ValueError("RUNNER_SANDBOX_IMAGE_MUST_BE_DIGEST_PINNED")
    if (type(config["cpu"]) is not int or not 1 <= config["cpu"] <= 8
            or type(config["memory"]) is not str or not re.fullmatch(r"(256|512|1024|2048|4096)Mi", config["memory"])):
        raise ValueError("RUNNER_SANDBOX_RESOURCE_BOUND_INVALID")
    if type(config["reason"]) is not str or not 10 <= len(config["reason"].strip()) <= 4096:
        raise ValueError("RUNNER_SANDBOX_SCOPE_REASON_REQUIRED")
    if config["lifecycle"] != "ephemeral-stop-contained":
        raise ValueError("RUNNER_SANDBOX_LIFECYCLE_UNSUPPORTED")
    if profile["availability"] != "NOT_CLAIMED":
        raise ValueError("RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED")
    if profile["object_kind"] == "BOT":
        bindings = config.get("bindings")
        if (type(bindings) is not dict or set(bindings) != {"agent", "sim", "harness"}
                or any(not isinstance(v, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", v) for v in bindings.values())):
            raise ValueError("RUNNER_BOT_EXACT_BINDINGS_REQUIRED")
    return config


def _capture(argv: list[str], timeout: int, env: dict[str, str]) -> dict[str, Any]:
    """Bound each stream in memory and terminate the CLI on excess or timeout."""
    started = time.monotonic()
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=False, env=env)

    def read(pipe: Any, buffer: bytearray) -> None:
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                available = LIMIT - len(buffer)
                buffer.extend(chunk[:available])
                if len(chunk) > available:
                    overflow.set()
                    proc.kill()
                    break
        finally:
            pipe.close()

    readers = [threading.Thread(target=read, args=(pipe, buffer), daemon=True)
               for pipe, buffer in zip((proc.stdout, proc.stderr), buffers)]
    for thread in readers:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait(timeout=5)
    for thread in readers:
        thread.join(timeout=2)
    incomplete = any(thread.is_alive() for thread in readers)
    return {"argv": argv, "exit_code": proc.returncode,
            "stdout": bytes(buffers[0]).decode("utf-8", errors="replace"),
            "stderr": bytes(buffers[1]).decode("utf-8", errors="replace"),
            "stdout_sha256": _digest(bytes(buffers[0])), "stderr_sha256": _digest(bytes(buffers[1])),
            "timeout": timed_out, "output_limit": overflow.is_set(), "output_incomplete": incomplete,
            "elapsed_seconds": round(time.monotonic() - started, 6)}


def _ok(result: dict[str, Any]) -> bool:
    return result["exit_code"] == 0 and not any(result[k] for k in ("timeout", "output_limit", "output_incomplete"))


def _snapshot(root: Path, paths: list[str], destination: Path) -> dict[str, str]:
    if not 1 <= len(paths) <= 256:
        raise ValueError("RUNNER_SANDBOX_INPUT_CAPACITY")
    hashes: dict[str, str] = {}
    size = 0
    for name in sorted(set(paths)):
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name
                or not relative.parts or name != relative.as_posix()):
            raise ValueError("RUNNER_SANDBOX_INPUT_PATH_INVALID")
        source = root.joinpath(*relative.parts)
        if any(parent.is_symlink() for parent in (source, *source.parents) if parent != root.parent):
            raise ValueError("RUNNER_SANDBOX_INPUT_SYMLINK")
        if not source.resolve(strict=True).is_relative_to(root) or not source.is_file():
            raise ValueError("RUNNER_SANDBOX_INPUT_OUTSIDE_ROOT")
        with source.open("rb") as stream:
            data = stream.read(8 * LIMIT - size + 1)
        size += len(data)
        if size > 8 * LIMIT:
            raise ValueError("RUNNER_SANDBOX_INPUT_CAPACITY")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[name] = _digest(data)
    return hashes


def _binding(detail: dict[str, Any], config: dict[str, Any], token: str) -> dict[str, Any]:
    if (detail.get("labels", {}).get("vstd-run") != token or detail.get("workspace") != config["workspace"]
            or not detail.get("id") or detail.get("phase") != "Ready"):
        raise ValueError("RUNNER_SANDBOX_IDENTITY_OR_READINESS_DIFFERS")
    policy = detail.get("policy", {})
    for key in ("version", "filesystem_policy", "landlock", "process"):
        if policy.get(key) != POLICY[key]:
            raise ValueError("RUNNER_SANDBOX_EFFECTIVE_POLICY_DIFFERS")
    if policy.get("network_policies") or policy.get("network_middlewares"):
        raise ValueError("RUNNER_SANDBOX_UNEXPECTED_NETWORK_GRANT")
    admission = detail.get("configuration_admission") or {}
    if admission.get("state") != "accepted" or not admission.get("policy_hash") or not detail.get("main_process_instance_id"):
        raise ValueError("RUNNER_SANDBOX_POLICY_ADMISSION_NOT_ESTABLISHED")
    return {"id": detail["id"], "instance": detail["main_process_instance_id"],
            "policy_hash": admission["policy_hash"], "config_revision": admission.get("config_revision"),
            "policy": policy}


def run(request: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"schema_version": "verifier-openshell-result-1", "status": "UNKNOWN",
        "sandbox_status": "NOT_ESTABLISHED", "execution_performed": False,
        "blockers": [], "commands": [], "cleanup": "NOT_CREATED", "obligation_status": "UNKNOWN",
        "claim_boundary": "Fresh sandbox execution and named probes only. No complete containment, corrigibility, availability, physics or object-conformance claim."}
    token = uuid.uuid4().hex
    # OpenShell 0.1.3 permits at most 19 name characters. The full random
    # ownership token remains in the label and is checked before any mutation.
    name = "vstd-" + token[:14]
    created = False
    cli: list[str] = []
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENSHELL_")}
    env["OPENSHELL_TELEMETRY_ENABLED"] = "false"

    def call(args: list[str], timeout: int = 30) -> dict[str, Any]:
        record = _capture([*cli, *args], timeout, env)
        result["commands"].append(record)
        return record

    def require(args: list[str], timeout: int = 30) -> dict[str, Any]:
        record = call(args, timeout)
        if not _ok(record):
            raise RuntimeError("RUNNER_OPENSHELL_COMMAND_INCOMPLETE")
        return record

    def execute(argv: list[str], timeout: int = 15, *, workdir: str = "/sandbox") -> dict[str, Any]:
        return call(["sandbox", "exec", "-n", name, "--no-tty", "--no-login-shell",
                     "--env", "BASH_ENV=/dev/null", "--env", "ENV=/dev/null",
                     "--env", "TMPDIR=/sandbox", "--workdir", workdir,
                     "--timeout", str(timeout), "--", *argv], timeout + 10)

    try:
        if request.get("schema_version") != "verifier-sandbox-request-1":
            raise ValueError("RUNNER_SANDBOX_REQUEST_VERSION")
        config = _config(request["config"], request["profile"])
        result["config"] = config
        result["adapter_sha256"] = _digest(Path(__file__).read_bytes())
        executable = shutil.which("openshell")
        if executable is None:
            raise FileNotFoundError("RUNNER_OPENSHELL_CLI_MISSING")
        cli = [str(Path(executable).resolve())]
        version = require(["--version"])
        if version["stdout"].strip() != "openshell " + VERSION:
            raise ValueError("RUNNER_OPENSHELL_VERSION_DIFFERS")
        result["cli_sha256"] = _digest(Path(executable).read_bytes())
        cli += ["--gateway", config["gateway"], "--workspace", config["workspace"], "--color", "never"]
        gateways = _json(require(["gateway", "list", "--output", "json"])["stdout"])
        if type(gateways) is not list or not any(type(g) is dict and g.get("name") == config["gateway"] for g in gateways):
            raise RuntimeError("RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED")
        gateway = _json(require(["gateway", "info", "--output", "json"])["stdout"])
        if (type(gateway) is not dict or gateway.get("status") != "healthy"
                or gateway.get("version") != VERSION or gateway.get("gateway") != config["gateway"]):
            raise ValueError("RUNNER_OPENSHELL_GATEWAY_VERSION_OR_HEALTH_DIFFERS")
        result["gateway_observation"] = gateway
        root = Path(request["root"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="vstd-openshell-") as staging:
            stage = Path(staging)
            source = stage / "source"
            source.mkdir()
            hashes = _snapshot(root, [request["entry"], *request["inputs"]], source)
            result["source_sha256"] = hashes
            policy = stage / "policy.json"
            policy.write_text(json.dumps(POLICY, sort_keys=True), encoding="utf-8")
            result["requested_policy_sha256"] = _digest(policy.read_bytes())
            # Set ownership BEFORE the call: a client timeout can still create compute.
            created = True
            result["sandbox_name"] = name
            result["cleanup"] = "UNKNOWN"
            require(["sandbox", "create", "--name", name, "--from", config["image"],
                "--cpu", str(config["cpu"]), "--memory", config["memory"], "--policy", str(policy),
                "--no-auto-providers", "--approval-mode", "manual", "--restart-policy", "never",
                "--label", "vstd-run=" + token, "--detach", "--no-tty", "--output", "json",
                "--", "/bin/sleep", "infinity"], 120)
            detail = _json(require(["sandbox", "get", name, "--output", "json"])["stdout"])
            bound = _binding(detail, config, token)
            result["binding_before"] = bound
            probes = execute(["python3", "-I", "-B", "-c", PROBE])
            if not _ok(probes):
                raise RuntimeError("RUNNER_SANDBOX_NEGATIVE_CONTROLS_NOT_ESTABLISHED")
            result["controls"] = _json(probes["stdout"])
            if (type(result["controls"]) is not dict or set(result["controls"]) != CONTROL_NAMES
                    or not all(v is True for v in result["controls"].values())):
                raise ValueError("RUNNER_SANDBOX_NEGATIVE_CONTROL_FAILED")
            parents = sorted({str(PurePosixPath("/sandbox/source") / PurePosixPath(p).parent) for p in hashes})
            mkdir = execute(["python3", "-I", "-B", "-c",
                "import pathlib,sys; [pathlib.Path(p).mkdir(parents=True,exist_ok=True) for p in sys.argv[1:]]", *parents])
            if not _ok(mkdir):
                raise RuntimeError("RUNNER_SANDBOX_STAGING_UNAVAILABLE")
            for path in hashes:
                require(["sandbox", "upload", name, str(source / path), "/sandbox/source/" + path, "--no-git-ignore"])
            check_command = ["python3", "-I", "-B", "-c", SOURCE_CHECK, json.dumps(hashes, sort_keys=True)]
            if not _ok(execute(check_command)):
                raise ValueError("RUNNER_SANDBOX_SOURCE_BINDING_DIFFERS")
            result["execution_attempted"] = True
            subject = execute(request["argv"], request["timeout"], workdir="/sandbox/source")
            # A CLI/transport failure does not tell us whether remote code ran.
            result["execution_performed"] = True if _ok(subject) else None
            result["execution"] = subject
            if not _ok(execute(check_command)):
                raise ValueError("RUNNER_SANDBOX_SOURCE_CHANGED")
            after = _binding(_json(require(["sandbox", "get", name, "--output", "json"])["stdout"]), config, token)
            result["binding_after"] = after
            if bound != after:
                raise ValueError("RUNNER_SANDBOX_BINDING_CHANGED")
            result["sandbox_status"] = "BOUNDED_PROBES_PASS"
            result["status"] = "PASS" if _ok(subject) else (
                "UNKNOWN" if any(subject[k] for k in ("timeout", "output_limit", "output_incomplete")) else "FAIL")
            if not _ok(subject):
                result["blockers"].append("RUNNER_OPENSHELL_EXECUTION_INCOMPLETE" if result["status"] == "UNKNOWN"
                                          else "RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED")
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc)
        result["blockers"].append(code if code.startswith("RUNNER_") else "RUNNER_OPENSHELL_UNAVAILABLE_OR_INVALID_RESPONSE")
        result["status"] = "FAIL" if isinstance(exc, ValueError) else "UNKNOWN"
    finally:
        if created:
            try:
                record = require(["sandbox", "get", name, "--output", "json"])
                owned = _json(record["stdout"])
                if owned.get("labels", {}).get("vstd-run") != token:
                    raise ValueError("RUNNER_SANDBOX_CLEANUP_OWNERSHIP_DIFFERS")
                require(["sandbox", "stop", name], 45)
                stopped = _json(require(["sandbox", "get", name, "--output", "json"])["stdout"])
                if stopped.get("phase") != "Stopped" or stopped.get("id") != owned.get("id"):
                    raise ValueError("RUNNER_SANDBOX_STOP_NOT_ESTABLISHED")
                result["cleanup"] = "STOPPED"
                require(["sandbox", "delete", name])
                for _ in range(5):
                    listing = _json(require(["sandbox", "list", "--selector", "vstd-run=" + token, "--output", "json"])["stdout"])
                    if listing.get("sandboxes") == [] and listing.get("next_page_token") == "":
                        result["cleanup"] = "DELETED"
                        break
                    time.sleep(0.2)
                if result["cleanup"] != "DELETED":
                    raise RuntimeError("RUNNER_SANDBOX_DELETE_NOT_ESTABLISHED")
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
                result["blockers"].append("RUNNER_SANDBOX_CLEANUP_NOT_ESTABLISHED")
                if result["status"] == "PASS":
                    result["status"] = "UNKNOWN"
    if "config" in result and "adapter_sha256" in result:
        from .environment import represent_environment
        result["environment"] = represent_environment(result, request["profile"], token)
    return result
