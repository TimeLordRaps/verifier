"""Native-language process adapters; no verification obligation is discharged.

Structured Query Language (SQL) means SQLite, JavaScript means Node.js, C and
C++ mean GCC, and Java means the Java 11+ single-source launcher. Fortran uses
GNU Fortran 2018, Lisp uses Steel Bank Common Lisp (SBCL), Prolog uses SWI-Prolog,
and PHP uses its command-line interpreter without host configuration. C# uses the
dotnet command-line interface (CLI) in a temporary project whose framework follows the
installed software development kit (SDK) major version, Go uses module-off ``go build`` with network and
workspace lookups disabled, R runs ``Rscript --vanilla``, Swift uses ``swiftc``, and
Julia runs with startup and history files disabled. COBOL, Object Pascal, Ada,
Objective-C and Assembly are batch-two adapters implemented in ``extended_batch_two``
and reached only through ``command``; the host runner admits them only by explicit name.
Visual Basic (.NET), Scratch, MATLAB and SAS are batch-three adapters in
``extended_batch_three`` with the same explicit reach; Classic Visual Basic is NOT_ESTABLISHED and
refuses with RUNNER_LANGUAGE_UNSUPPORTED before any lookup or process. No
shell, automatic package installation, project build scripts or language fallback.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import shutil
import sys
from typing import Any

from . import extended_batch_three, extended_batch_two

PROTOCOL = "verifier-language-runner-1"
TOOLS = {"javascript": "node", "c": "gcc", "cpp": "g++", "java": "java",
         "rust": "rustc", "perl": "perl", "fortran": "gfortran", "php": "php",
         "lisp": "sbcl", "prolog": "swipl", "csharp": "dotnet", "go": "go",
         "r": "Rscript", "swift": "swiftc", "julia": "julia"}
SUFFIXES = {"javascript": {".js", ".cjs", ".mjs"}, "c": {".c"}, "cpp": {".cpp", ".cc", ".cxx"},
            "java": {".java"}, "rust": {".rs"}, "perl": {".pl"}, "sql": {".sql"},
            "fortran": {".f", ".f90", ".f95", ".f03", ".f08"}, "php": {".php"},
            "lisp": {".lisp", ".lsp", ".cl"}, "prolog": {".pl", ".pro"},
            "csharp": {".cs"}, "go": {".go"}, "r": {".r"}, "swift": {".swift"},
            "julia": {".jl"}}
# Batch-two names are registered from their single source in extended_batch_two, which keeps
# the worker, deadlines and argument checks; nothing is copied here.
TOOLS.update({name: spec["tool"] for name, spec in extended_batch_two.LANGUAGES.items()})
SUFFIXES.update({name: set(spec["suffixes"]) for name, spec in extended_batch_two.LANGUAGES.items()})
# The same Python-hosted worker runs on the host or inside the selected sandbox.
# Compiler artifacts have a fresh private directory; compilation failure never
# falls through to an old executable. The outer runner bounds the whole run.
WORKER = '''import json, os, pathlib, sqlite3, subprocess, sys, tempfile
language, tool, entry, *args = sys.argv[1:]
if language == "sql":
    if args:
        raise SystemExit("SQLite script runner takes no positional arguments")
    db = sqlite3.connect(":memory:")
    db.enable_load_extension(False)
    db.set_authorizer(lambda action, *rest: sqlite3.SQLITE_DENY if action in
                      (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH) else sqlite3.SQLITE_OK)
    statement = ""
    for char in pathlib.Path(entry).read_text(encoding="utf-8"):
        statement += char
        if char == ";" and sqlite3.complete_statement(statement):
            cursor = db.execute(statement)
            if cursor.description:
                print(json.dumps(cursor.fetchall(), allow_nan=False))
            statement = ""
    if statement.strip():
        cursor = db.execute(statement)
        if cursor.description:
            print(json.dumps(cursor.fetchall(), allow_nan=False))
    db.close()
else:
    with tempfile.TemporaryDirectory(prefix="vstd-compile-") as directory:
        base = pathlib.Path(directory)
        target = str(base / ("subject.exe" if os.name == "nt" else "subject"))
        if language in {"c", "cpp", "rust", "fortran"}:
            flags = {"c": ["-std=c17"], "cpp": ["-std=c++17"], "rust": ["--edition=2021"],
                     "fortran": ["-std=f2018", "-J", directory]}[language]
            compiled = subprocess.run([tool, *flags, entry, "-o", target], shell=False,
                                      cwd=directory if language == "fortran" else None)
        elif language == "go":
            # Module mode, workspaces, proxies and toolchain downloads are all off; cgo needs no C compiler.
            env = dict(os.environ, GO111MODULE="off", GOTOOLCHAIN="local", GOPROXY="off",
                       GOWORK="off", GOFLAGS="", CGO_ENABLED="0")
            compiled = subprocess.run([tool, "build", "-o", target, entry], shell=False, env=env)
        elif language == "swift":
            compiled = subprocess.run([tool, "-o", target, entry], shell=False)
        elif language == "csharp":
            # A temporary project compiles a private copy of the subject; the SDK major version picks the framework.
            env = dict(os.environ, DOTNET_CLI_HOME=directory, DOTNET_CLI_TELEMETRY_OPTOUT="1",
                       DOTNET_NOLOGO="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
                       MSBUILDDISABLENODEREUSE="1", NUGET_PACKAGES=str(base / "nuget"))
            version = subprocess.run([tool, "--version"], shell=False, env=env, capture_output=True)
            if version.returncode:
                raise SystemExit(version.returncode)
            major = version.stdout.decode("utf-8", errors="replace").strip().split(".", 1)[0]
            if not major.isdigit():
                raise SystemExit("RUNNER_TOOLCHAIN_MISSING:dotnet")
            (base / "subject.cs").write_bytes(pathlib.Path(entry).read_bytes())
            (base / "subject.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
                f'<TargetFramework>net{major}.0</TargetFramework><AssemblyName>subject</AssemblyName>'
                '<NuGetAudit>false</NuGetAudit></PropertyGroup></Project>', encoding="utf-8")
            compiled = subprocess.run([tool, "build", str(base / "subject.csproj"), "--nologo",
                                       "-o", str(base / "out")], shell=False, env=env)
            target = str(base / "out" / ("subject.exe" if os.name == "nt" else "subject"))
        else:
            raise SystemExit("RUNNER_DIALECT_UNSUPPORTED")
        if compiled.returncode:
            raise SystemExit(compiled.returncode)
        raise SystemExit(subprocess.run([target, *args], shell=False).returncode)
'''


def command(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("language") in extended_batch_two.LANGUAGES:
        return extended_batch_two.command(request)
    # Batch-three names stay out of TOOLS and SUFFIXES: the batch-two package test pins those sets exactly.
    if request.get("language") in extended_batch_three.LANGUAGES:
        return extended_batch_three.command(request)
    language = request["language"]
    if request["schema_version"] != PROTOCOL or language not in SUFFIXES:
        raise ValueError("RUNNER_EXTENSION_PROTOCOL_DIFFERS")
    environment = request.get("environment", "host")
    if type(environment) is not str or environment not in {"host", "sandbox-linux"}:
        raise ValueError("RUNNER_ENVIRONMENT_UNSUPPORTED")
    remote = environment == "sandbox-linux"
    entry = (PurePosixPath(request["root"]) if remote else Path(request["root"])) / request["entry"]
    if entry.suffix.lower() not in SUFFIXES[language]:
        raise ValueError("RUNNER_DIALECT_UNSUPPORTED")
    args = request["arguments"]
    python = "python3" if remote else sys.executable
    tool = TOOLS.get(language, "sqlite3")
    if not remote and language != "sql":
        # Do not resolve an executable from the subject's current directory.
        paths = [p for p in os.get_exec_path() if p and Path(p).resolve() != Path(request["root"]).resolve()]
        resolved = shutil.which(tool, path=os.pathsep.join(paths))
        if resolved is None:
            raise FileNotFoundError(f"RUNNER_TOOLCHAIN_MISSING:{tool}")
        tool = str(Path(resolved).resolve())
    if language in {"c", "cpp", "rust", "sql", "fortran", "csharp", "go", "swift"}:
        argv = [python, "-I", "-B", "-c", WORKER, language, tool, str(entry), *args]
    elif language == "php":
        argv = [tool, "-n", "-f", str(entry), "--", *args]
    elif language == "lisp":
        argv = [tool, "--script", str(entry), *args]
    elif language == "prolog":
        argv = [tool, "-q", "--on-error=halt", "-f", "none", "-F", "none",
                "-s", str(entry), "-t", "halt", "--", *args]
    elif language == "r":
        # --vanilla implies --no-save, --no-restore, --no-environ and --no-init-file.
        argv = [tool, "--vanilla", str(entry), *args]
    elif language == "julia":
        argv = [tool, "--startup-file=no", "--history-file=no", "--non-interactive", "--", str(entry), *args]
    else:
        argv = [tool, str(entry), *args]
    return {"schema_version": PROTOCOL, "language": language, "argv": argv}

