"""Batch-two native adapters: COBOL, Object Pascal, Ada, Objective-C and Assembly.

Reachable through the package, not the host command-line interface (CLI): ``vstd_languages.command``
dispatches these five names here, and ``vstd_languages.TOOLS``, ``SUFFIXES`` and the
``verifier.language_runners`` entry points list them. The host runner
(``verifier.runtime.language_runners``) still admits only its fixed sixteen-name
package set, so the installed CLI cannot select these names until that registry is
integrated. This module mirrors the closed ``verifier-language-runner-1`` request/argv
shape and imports nothing from the package ``__init__``.

Dialects are explicit and never conflated:

- COBOL: GnuCOBOL ``cobc -x`` with the default fixed-form source format.
- Object Pascal: Free Pascal ``fpc -n -Mobjfpc`` (no configuration file, objfpc mode).
- Ada: GNAT ``gnatmake`` for one main procedure body in a single unit.
- Objective-C: ``clang -x objective-c``; no Objective-C runtime or frameworks are
  selected, so the specimens prove the driver route only, not Objective-C object
  semantics. Linking an Objective-C program needs a runtime on the target platform.
- Assembly: GNU ``as`` AT&T syntax for x86-64 assembled and linked by the GCC driver
  (``gcc -x assembler``) for ``.s`` sources.

Worker outcomes reach the host as exit codes only, and the host reads only those: 0 is
a candidate PASS, a nonzero code is FAIL, and no code is UNKNOWN. The stderr line names
the cause. Refusals use the core vocabulary where one exists (``RUNNER_TOOLCHAIN_MISSING``,
``RUNNER_RESOURCE_UNAVAILABLE``, ``RUNNER_DIALECT_UNSUPPORTED``). Deadlines and the output
cap print the extension-only ``VSTD_EXTENSION_TIMEOUT`` or
``VSTD_EXTENSION_OUTPUT_LIMIT`` with ``cleanup=UNKNOWN``, and exit with reserved codes
124 or 125. Current core maps those exact integers to fixed UNKNOWN blockers without
reading the line. These names remain unreachable until the host registry integrates them.

Environment: an absent or ``host`` declaration constructs a trusted-local command after
host tool resolution. ``sandbox-linux`` constructs the same bounded Python worker with
``python3`` and the declared tool name under ``/sandbox/source``; it performs no host tool
lookup and is only an argv contract for core's optional OpenShell environment. Anything
else is refused as ``RUNNER_ENVIRONMENT_UNSUPPORTED`` before lookup. The worker inherits
the selected environment's process variables; nothing in the request can inject them.

Cleanup: a deadline or cap stop kills the owned child. On Windows the child's tree is
first stopped with ``taskkill /T /F`` by its process identifier. The standard library
offers no Windows job object and no POSIX group kill that keeps the host's owned tree
intact, so descendant cleanup is not proved here and the stop line says ``cleanup=UNKNOWN``.
When core runs the worker, its owned tree (a process group on POSIX, a job object on
Windows) is the cleanup that can confirm descendant termination.

The worker compiles in a fresh temporary directory (its cwd, so compiler side files
stay out of the subject root), runs the built artifact only after a successful
compile, and each stream is capped at ``OUTPUT_BYTES``. Missing tools report
``RUNNER_TOOLCHAIN_MISSING:<tool>`` and never fall back.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import sys
from typing import Any

PROTOCOL = "verifier-language-runner-1"
MAX_ARGUMENTS = 32
MAX_ARGUMENT_BYTES = 4096
LANGUAGES: dict[str, dict[str, Any]] = {
    "cobol": {"tool": "cobc", "suffixes": (".cob", ".cbl"),
              "dialect": "GnuCOBOL cobc -x, fixed-form source (cobc default)"},
    "object-pascal": {"tool": "fpc", "suffixes": (".pas", ".pp"),
                      "dialect": "Free Pascal fpc -n -Mobjfpc (no configuration file, objfpc mode)"},
    "ada": {"tool": "gnatmake", "suffixes": (".adb",),
            "dialect": "GNAT gnatmake single main procedure body, default Ada language version"},
    "objective-c": {"tool": "clang", "suffixes": (".m",),
                    "dialect": "clang -x objective-c, no Objective-C runtime or frameworks selected"},
    "assembly": {"tool": "gcc", "suffixes": (".s",),
                 "dialect": "GNU as x86-64 AT&T syntax via the GCC driver (-x assembler)"},
}
# Compiler and subject output is confined to a fresh directory; the constants are the
# only deadline and cap inputs, and tests substitute them by exact text.
WORKER = '''import os, subprocess, sys, tempfile, time
COMPILE_SECONDS = 120
RUN_SECONDS = 60
OUTPUT_BYTES = 65536
TASKKILL = os.path.join(os.environ.get("SystemRoot") or "C:" "\\\\Windows", "System32", "taskkill.exe")
language, tool, entry, *args = sys.argv[1:]


def stop(proc):
    """Stop the owned child. On Windows the tree goes first, while children still link to its PID."""
    pid = getattr(proc, "pid", None)
    if os.name == "nt" and isinstance(pid, int) and os.path.exists(TASKKILL):
        try:
            subprocess.run([TASKKILL, "/T", "/F", "/PID", str(pid)], shell=False, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        proc.kill()
    except OSError:
        pass
    proc.wait()


def bounded(argv, cwd, seconds):
    """Start argv with a deadline and per-stream byte cap; the owned child is stopped on either."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(argv, shell=False, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        except OSError:
            return "SPAWN", None, b"", b""
        deadline = time.monotonic() + seconds
        verdict = None
        while proc.poll() is None:
            if time.monotonic() > deadline:
                verdict = "TIMEOUT"
            elif max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > OUTPUT_BYTES:
                verdict = "OUTPUT_LIMIT"
            if verdict:
                stop(proc)
                return verdict, None, b"", b""
            time.sleep(0.01)
        if max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > OUTPUT_BYTES:
            return "OUTPUT_LIMIT", None, b"", b""
        out.seek(0)
        err.seek(0)
        return "EXITED", proc.returncode, out.read(), err.read()


def exit_code(code):
    if code < 0:
        return min(128 - code, 255)
    return min(code, 255)


def refuse(line, code):
    sys.stderr.write(line + "\\n")
    sys.stderr.flush()
    raise SystemExit(code)


if language not in {"cobol", "object-pascal", "ada", "objective-c", "assembly"}:
    refuse("RUNNER_DIALECT_UNSUPPORTED", 1)
with tempfile.TemporaryDirectory(prefix="vstd-batch2-") as directory:
    target = os.path.join(directory, "subject.exe" if os.name == "nt" else "subject")
    if language == "cobol":
        build = [tool, "-x", "-o", target, entry]
    elif language == "object-pascal":
        build = [tool, "-n", "-Mobjfpc", "-FU" + directory, "-FE" + directory, "-o" + target, entry]
    elif language == "ada":
        build = [tool, "-D", directory, "-o", target, entry]
    elif language == "objective-c":
        build = [tool, "-x", "objective-c", "-o", target, entry]
    else:
        build = [tool, "-x", "assembler", "-o", target, entry]
    status, code, out, err = bounded(build, directory, COMPILE_SECONDS)
    if status == "SPAWN":
        # A toolchain that cannot start is reported as missing; the host lookup already resolved its path.
        refuse("RUNNER_TOOLCHAIN_MISSING:" + os.path.splitext(os.path.basename(tool))[0], 127)
    if status == "TIMEOUT":
        refuse("VSTD_EXTENSION_TIMEOUT:compile cleanup=UNKNOWN", 124)
    if status == "OUTPUT_LIMIT":
        refuse("VSTD_EXTENSION_OUTPUT_LIMIT:compile cleanup=UNKNOWN", 125)
    if code:
        sys.stderr.buffer.write(out + err)
        sys.stderr.flush()
        raise SystemExit(exit_code(code))
    status, code, out, err = bounded([target, *args], directory, RUN_SECONDS)
    if status == "SPAWN":
        refuse("RUNNER_RESOURCE_UNAVAILABLE:run", 126)
    if status == "TIMEOUT":
        refuse("VSTD_EXTENSION_TIMEOUT:run cleanup=UNKNOWN", 124)
    if status == "OUTPUT_LIMIT":
        refuse("VSTD_EXTENSION_OUTPUT_LIMIT:run cleanup=UNKNOWN", 125)
    sys.stdout.buffer.write(out)
    sys.stdout.flush()
    sys.stderr.buffer.write(err)
    sys.stderr.flush()
    raise SystemExit(exit_code(code))
'''


def command(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("schema_version") != PROTOCOL:
        raise ValueError("RUNNER_EXTENSION_PROTOCOL_DIFFERS")
    language = request.get("language")
    if language not in LANGUAGES:
        raise ValueError("RUNNER_LANGUAGE_UNSUPPORTED")
    environment = request.get("environment", "host")
    if type(environment) is not str or environment not in {"host", "sandbox-linux"}:
        raise ValueError("RUNNER_ENVIRONMENT_UNSUPPORTED")
    remote = environment == "sandbox-linux"
    arguments = request.get("arguments")
    if not isinstance(arguments, list) or len(arguments) > MAX_ARGUMENTS:
        raise ValueError("RUNNER_ARGUMENT_INVALID")
    for argument in arguments:
        if (not isinstance(argument, str) or "\x00" in argument
                or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES):
            raise ValueError("RUNNER_ARGUMENT_INVALID")
    root_text, entry = request.get("root"), request.get("entry")
    if not isinstance(root_text, str):
        raise ValueError("RUNNER_ROOT_INVALID")
    if not isinstance(entry, str) or not entry or "\x00" in entry:
        raise ValueError("RUNNER_ENTRY_INVALID")
    windows, posix = PureWindowsPath(entry), PurePosixPath(entry)
    if (windows.drive or windows.root or posix.is_absolute() or entry.startswith("-")
            or ".." in windows.parts or ".." in posix.parts):
        raise ValueError("RUNNER_ENTRY_INVALID")
    if remote:
        root = PurePosixPath(root_text)
        if not root.is_absolute() or root != PurePosixPath("/sandbox/source"):
            raise ValueError("RUNNER_ROOT_INVALID")
        if "\\" in entry:
            raise ValueError("RUNNER_ENTRY_INVALID")
        path: Path | PurePosixPath = root / posix
    else:
        if not Path(root_text).is_dir():
            raise ValueError("RUNNER_ROOT_INVALID")
        root = Path(root_text).resolve()
        path = (root / entry).resolve()
        if not path.is_file():
            raise ValueError("RUNNER_ENTRY_MISSING")
        if not path.is_relative_to(root):
            raise ValueError("RUNNER_ENTRY_OUTSIDE_ROOT")
    spec = LANGUAGES[language]
    if path.suffix.lower() not in spec["suffixes"]:
        raise ValueError("RUNNER_DIALECT_UNSUPPORTED")
    tool = spec["tool"]
    python = "python3" if remote else sys.executable
    if not remote:
        # Do not resolve the toolchain from the subject directory.
        search = [p for p in os.get_exec_path() if p and Path(p).resolve() != root]
        resolved = shutil.which(tool, path=os.pathsep.join(search))
        if resolved is None:
            raise FileNotFoundError(f"RUNNER_TOOLCHAIN_MISSING:{tool}")
        tool = str(Path(resolved).resolve())
    return {"schema_version": PROTOCOL, "language": language,
            "argv": [python, "-I", "-B", "-c", WORKER, language, tool, str(path), *arguments]}
