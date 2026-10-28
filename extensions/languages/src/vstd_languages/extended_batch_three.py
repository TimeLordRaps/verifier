"""Batch-three native adapters: Visual Basic (.NET), Scratch, MATLAB, SAS and Classic Visual Basic.

Visual Basic builds one temporary ``.vbproj`` with the dotnet command-line interface (CLI). Its
target framework follows the installed software development kit (SDK) major version, NuGet
audit is off, and restore reads only an empty private source. Scratch needs an explicitly
installed headless runner named ``scratch-vm-headless``. The ``.sb3`` archive must first pass
a closed ZIP archive format (ZIP) and project.json shape check, and that static check is never
reported as execution. MATLAB runs a single-file script copied under a safe identifier with
``matlab -nostartup -batch``. SAS runs a single-file program with ``sas -sysin`` and bounded
log and listing files in a private directory. Classic Visual Basic (VB6) is fail-closed
NOT_ESTABLISHED: no verified noninteractive compiler contract exists here, and cscript/VBScript
is never substituted; its command refuses with the closed code RUNNER_LANGUAGE_UNSUPPORTED
before any lookup or process. No shell, network, package installation, sibling dependency or
language fallback. The optional package callable routes these names here; core admits the
four implemented names only after explicit language selection.

Worker outcomes reach the host as exit codes, which the host reads as 0 candidate PASS, nonzero
FAIL, or no code UNKNOWN. Refusal lines reuse the core vocabulary where one exists. Deadlines and
the output cap print the extension-only ``VSTD_EXTENSION_TIMEOUT`` or
``VSTD_EXTENSION_OUTPUT_LIMIT`` with ``cleanup=UNKNOWN``, and exit with reserved codes
124 or 125. Current core maps those exact integers to fixed UNKNOWN blockers without
reading the line.
Environment: an absent or ``host`` declaration constructs a trusted-local command after
host tool resolution. ``sandbox-linux`` constructs the same bounded Python worker with
``python3`` and the declared tool name under ``/sandbox/source``; it performs no host lookup
and is only an argv contract for core's optional OpenShell environment. Other declarations
are ``RUNNER_ENVIRONMENT_UNSUPPORTED``. The child inherits the selected environment; cleanup:
a stop kills the owned child, and on Windows its tree first with ``taskkill /T /F``; descendants
are not proved here, and the host's owned tree is what can confirm them.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sys
from typing import Any
import zlib

PROTOCOL = "verifier-language-runner-1"
MAX_ARGUMENTS = 32
MAX_ARGUMENT_BYTES = 4096
LANGUAGES: dict[str, dict[str, Any]] = {
    "visual-basic": {"tool": "dotnet", "suffixes": {".vb"}, "status": "IMPLEMENTED",
                     "dialect": "Visual Basic .NET in a temporary SDK project"},
    "scratch": {"tool": "scratch-vm-headless", "suffixes": {".sb3"}, "status": "IMPLEMENTED",
                "dialect": "Scratch 3 project archive for an explicitly installed headless runner"},
    "matlab": {"tool": "matlab", "suffixes": {".m"}, "status": "IMPLEMENTED",
               "dialect": "MATLAB single-file script in batch mode"},
    "sas": {"tool": "sas", "suffixes": {".sas"}, "status": "IMPLEMENTED",
            "dialect": "SAS single-file batch program"},
    "classic-visual-basic": {"tool": None, "suffixes": {".bas", ".frm", ".cls"},
                             "status": "NOT_ESTABLISHED", "dialect": "Visual Basic 6 (VB6)"},
}
MATLAB_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,62}")

# One source of truth for the Scratch archive shape: the host runs it before returning
# argv, and the worker runs it again on the private copy it actually starts.
SB3_CHECK = r'''import json, re, stat, zipfile, zlib
SB3_MEMBERS = 512
SB3_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
SB3_PROJECT_JSON_BYTES = 16 * 1024 * 1024
SB3_ASSET = re.compile(r"[A-Za-z0-9_-]{1,128}\.(svg|png|jpe?g|gif|wav|mp3)")


def sb3_problem(path):
    """None for a closed Scratch 3 ZIP shape; otherwise one fixed reason token."""
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile):
        return "not-zip"
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > SB3_MEMBERS:
            return "member-count"
        if len(set(names)) != len(names):
            return "duplicate-member"
        if "project.json" not in names:
            return "missing-project-json"
        total = 0
        for info in infos:
            if stat.S_ISLNK(info.external_attr >> 16):
                return "member-symlink"
            if info.filename != "project.json" and not SB3_ASSET.fullmatch(info.filename):
                return "member-name"
            total += info.file_size
            if total > SB3_UNCOMPRESSED_BYTES:
                return "uncompressed-size"
        if archive.getinfo("project.json").file_size > SB3_PROJECT_JSON_BYTES:
            return "project-json-size"
        try:
            project = json.loads(archive.read("project.json").decode("utf-8"))
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error):
            return "project-json-invalid"
    targets = project.get("targets") if isinstance(project, dict) else None
    if not isinstance(targets, list) or not all(
            isinstance(t, dict) and isinstance(t.get("name"), str) and isinstance(t.get("blocks"), dict)
            for t in targets):
        return "project-shape"
    if sum(t.get("isStage") is True for t in targets) != 1:
        return "project-shape"
    return None
'''
_SB3_NAMESPACE: dict[str, Any] = {}
exec(SB3_CHECK, _SB3_NAMESPACE)  # Fixed module text above; no external input reaches it.
sb3_problem = _SB3_NAMESPACE["sb3_problem"]

# The worker runs as a separate Python process from a private temporary directory. Output
# is file-backed and bounded before anything is echoed; the owned child is stopped on timeout,
# and as soon as its output passes the cap.
WORKER = SB3_CHECK + '''
import os, pathlib, subprocess, sys, tempfile, time
language, tool, entry, *args = sys.argv[1:]
PROCESS_SECONDS = 300
PROBE_SECONDS = 60
OUTPUT_BYTES = 65536
POLL_SECONDS = 0.05
TASKKILL = os.path.join(os.environ.get("SystemRoot") or "C:" "\\\\Windows", "System32", "taskkill.exe")


def refuse(line, code):
    sys.stderr.write(line + "\\n")
    sys.stderr.flush()
    return code


def tool_name(path):
    return os.path.splitext(os.path.basename(path))[0]


def stop(child):
    """Stop the owned child. On Windows the tree goes first, while children still link to its PID."""
    pid = getattr(child, "pid", None)
    if os.name == "nt" and isinstance(pid, int) and os.path.exists(TASKKILL):
        try:
            subprocess.run([TASKKILL, "/T", "/F", "/PID", str(pid)], shell=False, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        child.kill()
    except OSError:
        pass
    child.wait()


def run(argv, cwd, log, stream, stage="run", missing=None, env=None):
    """Run one child with a deadline and a file-size cap; return its exit code after printing any refusal."""
    with open(log, "wb") as out:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, shell=False, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=subprocess.STDOUT)
        except OSError:
            if missing is not None:
                return refuse("RUNNER_TOOLCHAIN_MISSING:" + missing, 127)
            return refuse("RUNNER_RESOURCE_UNAVAILABLE:" + stage, 126)
        deadline = time.monotonic() + PROCESS_SECONDS
        while True:
            try:
                code = child.wait(timeout=POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                # The file size is polled while the child runs, so a runaway child is stopped at the cap.
                timed_out = time.monotonic() > deadline
                overflowed = os.path.getsize(log) > OUTPUT_BYTES
                if timed_out or overflowed:
                    stop(child)
                    if timed_out:
                        return refuse(f"VSTD_EXTENSION_TIMEOUT:{stage} cleanup=UNKNOWN", 124)
                    return refuse(f"VSTD_EXTENSION_OUTPUT_LIMIT:{stage} cleanup=UNKNOWN", 125)
    if os.path.getsize(log) > OUTPUT_BYTES:
        return refuse(f"VSTD_EXTENSION_OUTPUT_LIMIT:{stage} cleanup=UNKNOWN", 125)
    stream.write(pathlib.Path(log).read_bytes())
    stream.flush()
    return code if code >= 0 else 128 - code


def sdk_major(tool, env):
    """The SDK major version, or a typed token when the probe cannot establish it."""
    try:
        version = subprocess.run([tool, "--version"], shell=False, env=env, capture_output=True,
                                 timeout=PROBE_SECONDS)
    except subprocess.TimeoutExpired:
        return None, "RUNNER_TOOLCHAIN_VERSION_UNKNOWN:dotnet"
    except OSError:
        return None, "RUNNER_TOOLCHAIN_MISSING:dotnet"
    major = version.stdout.decode("utf-8", errors="replace").strip().split(".", 1)[0]
    if version.returncode or not major.isdigit():
        return None, "RUNNER_TOOLCHAIN_VERSION_UNKNOWN:dotnet"
    return major, None


def visual_basic(tool, entry, args, base):
    env = dict(os.environ, DOTNET_CLI_HOME=str(base), DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1",
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", MSBUILDDISABLENODEREUSE="1", NUGET_PACKAGES=str(base / "nuget"))
    major, token = sdk_major(tool, env)
    if token:
        return refuse(token, 127)
    (base / "subject.vb").write_bytes(pathlib.Path(entry).read_bytes())
    (base / "nosource").mkdir()
    (base / "subject.vbproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        f'<TargetFramework>net{major}.0</TargetFramework><AssemblyName>subject</AssemblyName>'
        '<RootNamespace>subject</RootNamespace><Deterministic>true</Deterministic>'
        f'<NuGetAudit>false</NuGetAudit><RestoreSources>{base / "nosource"}</RestoreSources>'
        '</PropertyGroup></Project>', encoding="utf-8")
    built = run([tool, "build", str(base / "subject.vbproj"), "--nologo", "-o", str(base / "out")],
                str(base), base / "build.log", sys.stderr.buffer, "build", missing="dotnet", env=env)
    if built:
        return built
    return run([str(base / "out" / ("subject.exe" if os.name == "nt" else "subject")), *args],
               str(base), base / "run.log", sys.stdout.buffer, "run")


def scratch(tool, entry, base):
    copy = base / "project.sb3"
    copy.write_bytes(pathlib.Path(entry).read_bytes())
    problem = sb3_problem(copy)
    if problem:
        return refuse("RUNNER_CONTRACT_REJECTED: scratch project " + problem, 1)
    return run([tool, str(copy)], str(base), base / "runner.log", sys.stdout.buffer, "scratch",
               missing=tool_name(tool))


def matlab(tool, entry, base):
    script = base / (pathlib.Path(entry).stem + ".m")
    script.write_bytes(pathlib.Path(entry).read_bytes())
    return run([tool, "-nostartup", "-batch", script.stem], str(base), base / "matlab.log", sys.stdout.buffer,
               "matlab", missing=tool_name(tool))


def sas(tool, entry, base):
    source = base / "subject.sas"
    source.write_bytes(pathlib.Path(entry).read_bytes())
    log, listing = base / "sas.log", base / "sas.lst"
    code = run([tool, "-nosplash", "-noterminal", "-noautoexec", "-sysin", str(source),
                "-log", str(log), "-print", str(listing)], str(base), base / "console.log", sys.stderr.buffer,
               "sas", missing=tool_name(tool))
    if code:
        return code
    for artifact in (log, listing):
        if artifact.exists() and artifact.stat().st_size > OUTPUT_BYTES:
            return refuse("VSTD_EXTENSION_OUTPUT_LIMIT:sas cleanup=UNKNOWN", 125)
    if not log.exists():
        return refuse("RUNNER_RESOURCE_UNAVAILABLE:sas", 126)
    if any(line.startswith("ERROR") for line in log.read_text(encoding="utf-8", errors="replace").splitlines()):
        return 1
    if listing.exists():
        sys.stdout.buffer.write(listing.read_bytes())
        sys.stdout.buffer.flush()
    return 0


with tempfile.TemporaryDirectory(prefix="vstd-batch-three-") as directory:
    base = pathlib.Path(directory)
    if args and language != "visual-basic":
        code = refuse("RUNNER_ARGUMENT_VECTOR_INVALID", 1)
    elif language == "visual-basic":
        code = visual_basic(tool, entry, args, base)
    elif language == "scratch":
        code = scratch(tool, entry, base)
    elif language == "matlab":
        code = matlab(tool, entry, base)
    elif language == "sas":
        code = sas(tool, entry, base)
    else:
        code = refuse("RUNNER_DIALECT_UNSUPPORTED", 1)
raise SystemExit(code)
'''
WORKER_LAUNCHER = (
    "import base64,sys,zlib;exec(compile(zlib.decompress(base64.b85decode("
    "sys.argv.pop(1))).decode('utf-8'),'<vstd-batch-three-worker>','exec'))"
)
WORKER_PAYLOAD = base64.b85encode(zlib.compress(WORKER.encode("utf-8"))).decode("ascii")


def command(request: dict[str, Any]) -> dict[str, Any]:
    language = request["language"]
    if request["schema_version"] != PROTOCOL or language not in LANGUAGES:
        raise ValueError("RUNNER_EXTENSION_PROTOCOL_DIFFERS")
    environment = request.get("environment", "host")
    if type(environment) is not str or environment not in {"host", "sandbox-linux"}:
        raise ValueError("RUNNER_ENVIRONMENT_UNSUPPORTED")
    remote = environment == "sandbox-linux"
    spec = LANGUAGES[language]
    if spec["status"] != "IMPLEMENTED":
        # Core maps only listed codes, so the closed code is raised; NOT_ESTABLISHED remains the registry status.
        raise ValueError("RUNNER_LANGUAGE_UNSUPPORTED")
    if remote:
        root_text = request.get("root")
        if type(root_text) is not str or PurePosixPath(root_text) != PurePosixPath("/sandbox/source"):
            raise ValueError("RUNNER_ROOT_INVALID")
        entry: Path | PurePosixPath = _remote_entry(request.get("entry"), spec["suffixes"])
    else:
        root = Path(request["root"])
        entry = _entry(root, request["entry"], spec["suffixes"])
    if language == "matlab" and not MATLAB_NAME.fullmatch(entry.stem):
        raise ValueError("RUNNER_CONTRACT_REJECTED")
    if not remote and language == "scratch" and sb3_problem(entry) is not None:
        raise ValueError("RUNNER_CONTRACT_REJECTED")
    arguments = _arguments(request["arguments"])
    if arguments and language != "visual-basic":
        raise ValueError("RUNNER_ARGUMENT_VECTOR_INVALID")
    tool = spec["tool"] if remote else _tool(spec["tool"], root)
    python = "python3" if remote else sys.executable
    return {"schema_version": PROTOCOL, "language": language,
            "argv": [python, "-I", "-B", "-c", WORKER_LAUNCHER, WORKER_PAYLOAD,
                     language, tool, str(entry), *arguments]}


def _remote_entry(name: Any, suffixes: set[str]) -> PurePosixPath:
    """Admit one lexical file under the fixed OpenShell staging root without host reads."""

    if type(name) is not str or not name or "\x00" in name or name.startswith("-") or "\\" in name:
        raise ValueError("RUNNER_CONTRACT_REJECTED")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "" in relative.parts:
        raise ValueError("RUNNER_ENTRY_OUTSIDE_ROOT")
    if relative.suffix.lower() not in suffixes:
        raise ValueError("RUNNER_DIALECT_UNSUPPORTED")
    return PurePosixPath("/sandbox/source") / relative


def _entry(root: Path, name: Any, suffixes: set[str]) -> Path:
    """Admit one relative file under the root; symlink escapes resolve outside and fail."""
    if not isinstance(name, str) or not name or "\x00" in name or name.startswith("-"):
        raise ValueError("RUNNER_CONTRACT_REJECTED")
    parts = re.split(r"[\\/]", name)
    windows, posix = PureWindowsPath(name), PurePosixPath(name)
    if windows.drive or windows.root or posix.is_absolute() or ".." in parts or "" in parts:
        raise ValueError("RUNNER_ENTRY_OUTSIDE_ROOT")
    if os.path.splitext(parts[-1])[1].lower() not in suffixes:
        raise ValueError("RUNNER_DIALECT_UNSUPPORTED")
    candidate = root / name
    if not candidate.is_file():
        raise ValueError("RUNNER_ENTRY_MISSING")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("RUNNER_ENTRY_OUTSIDE_ROOT")
    # The dialect is the declared name's suffix; an in-root link must not retarget it to another dialect.
    if os.path.splitext(resolved.name)[1].lower() not in suffixes:
        raise ValueError("RUNNER_DIALECT_UNSUPPORTED")
    return resolved


def _arguments(values: Any) -> list[str]:
    if not isinstance(values, list) or len(values) > MAX_ARGUMENTS:
        raise ValueError("RUNNER_ARGUMENT_VECTOR_INVALID")
    for value in values:
        if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError("RUNNER_ARGUMENT_VECTOR_INVALID")
    return list(values)


def _tool(name: str, root: Path) -> str:
    """Resolve only from PATH entries outside the subject root; a missing tool never falls back."""
    paths = [p for p in os.get_exec_path() if p and Path(p).resolve() != root.resolve()]
    resolved = shutil.which(name, path=os.pathsep.join(paths))
    if resolved is None:
        raise FileNotFoundError(f"RUNNER_TOOLCHAIN_MISSING:{name}")
    return str(Path(resolved).resolve())
