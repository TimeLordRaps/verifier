"""Real toolchain regressions; missing optional toolchains are explicit skips.

Structured Query Language (SQL) is the SQLite dialect, not an arbitrary server.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "extensions/languages/src"))
    import vstd_languages
    return vstd_languages


CASES = [
    ("javascript", "main.js", "console.log('native-42');", "node"),
    ("c", "main.c", '#include <stdio.h>\nint main(void){puts("native-42");return 0;}', "gcc"),
    ("cpp", "main.cpp", '#include <iostream>\nint main(){std::cout << "native-42\\n";}', "g++"),
    ("java", "Main.java", 'class Main { public static void main(String[] args) { System.out.println("native-42"); }}', "java"),
    ("rust", "main.rs", 'fn main(){println!("native-42");}', "rustc"),
    ("perl", "main.pl", 'print "native-42\\n";', "perl"),
    ("sql", "main.sql", "create table t(x text); insert into t values('native-42'); select x from t;", None),
    ("fortran", "main.f90", 'program main\nprint *, "native-42"\nend program main', "gfortran"),
    ("php", "main.php", '<?php echo "native-42\\n";', "php"),
    ("lisp", "main.lisp", '(format t "native-42~%")', "sbcl"),
    ("prolog", "main.pro", ":- initialization(main, main).\nmain :- writeln('native-42').", "swipl"),
    ("csharp", "Main.cs", 'class Main { static void Main() { System.Console.WriteLine("native-42"); } }', "dotnet"),
    ("go", "main.go", 'package main\nimport "fmt"\nfunc main() { fmt.Println("native-42") }', "go"),
    ("r", "main.r", 'cat("native-42\\n")', "Rscript"),
    ("swift", "main.swift", 'print("native-42")', "swiftc"),
    ("julia", "main.jl", 'println("native-42")', "julia"),
]


# Compiled fixtures create scanner-visible binaries such as ``subject.exe`` in
# an isolated temporary directory.  Merely having a compiler on PATH is not
# consent to run it during the ordinary dependency-free regression suite.
COMPILED_LANGUAGES = {"c", "cpp", "csharp", "fortran", "go", "rust", "swift"}


def _native_toolchain_authorized(language: str) -> bool:
    return (language not in COMPILED_LANGUAGES
            or os.environ.get("VSTD_RUN_NATIVE_TOOLCHAINS") == "1")


def test_compiled_toolchains_require_exact_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VSTD_RUN_NATIVE_TOOLCHAINS", raising=False)
    assert not _native_toolchain_authorized("c")
    assert _native_toolchain_authorized("javascript")
    monkeypatch.setenv("VSTD_RUN_NATIVE_TOOLCHAINS", "true")
    assert not _native_toolchain_authorized("rust")
    monkeypatch.setenv("VSTD_RUN_NATIVE_TOOLCHAINS", "1")
    assert all(_native_toolchain_authorized(language)
               for language in COMPILED_LANGUAGES)


@pytest.mark.parametrize("language,name,source,tool", CASES)
def test_native_toolchain_positive_and_invalid_source(adapter, tmp_path, language, name, source, tool) -> None:
    if not _native_toolchain_authorized(language):
        pytest.skip(
            "NATIVE_TOOLCHAIN_NOT_AUTHORIZED: set VSTD_RUN_NATIVE_TOOLCHAINS=1 "
            "to compile isolated temporary fixtures"
        )
    if tool and shutil.which(tool) is None:
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: explicitly selected native toolchain " + tool)
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    response = adapter.command({"schema_version": adapter.PROTOCOL, "language": language,
                                "root": str(tmp_path), "entry": name, "arguments": []})
    good = subprocess.run(response["argv"], cwd=tmp_path, capture_output=True, timeout=30)
    assert good.returncode == 0, good.stderr.decode(errors="replace")
    assert b"native-42" in good.stdout
    path.write_text("<?php this is not valid {{{" if language == "php" else
                    "this is not valid {{{ code for this dialect", encoding="utf-8")
    bad = subprocess.run(response["argv"], cwd=tmp_path, capture_output=True, timeout=30)
    assert bad.returncode != 0
    assert b"native-42" not in bad.stdout
    assert list(tmp_path.iterdir()) == [path]  # No compiler outputs in the subject repo.


def test_missing_runtime_and_wrong_dialect_fail_explicitly(adapter, tmp_path, monkeypatch) -> None:
    request = {"schema_version": adapter.PROTOCOL, "language": "javascript", "root": str(tmp_path),
               "entry": "main.js", "arguments": []}
    monkeypatch.setattr(adapter.shutil, "which", lambda *a, **kw: None)
    with pytest.raises(FileNotFoundError, match="RUNNER_TOOLCHAIN_MISSING"):
        adapter.command(request)
    request["entry"] = "main.ts"
    with pytest.raises(ValueError, match="RUNNER_DIALECT_UNSUPPORTED"):
        adapter.command(request)


def test_remote_adapter_never_uses_host_toolchain(adapter, monkeypatch) -> None:
    monkeypatch.setattr(adapter.shutil, "which", lambda *a, **kw: pytest.fail("host resolution"))
    response = adapter.command({"schema_version": adapter.PROTOCOL, "language": "javascript",
        "root": "/sandbox/source", "entry": "nested/main.js", "arguments": ["; echo no-shell"],
        "environment": "sandbox-linux"})
    assert response["argv"] == ["node", "/sandbox/source/nested/main.js", "; echo no-shell"]


@pytest.mark.parametrize("environment", [None, {"PATH": "/subject/bin"}, "container", 0])
def test_environment_injection_is_refused_before_tool_lookup(
    adapter, tmp_path, monkeypatch, environment
) -> None:
    monkeypatch.setattr(
        adapter.shutil, "which", lambda *a, **kw: pytest.fail("lookup before environment admission")
    )
    request = {
        "schema_version": adapter.PROTOCOL,
        "language": "javascript",
        "root": str(tmp_path),
        "entry": "main.js",
        "arguments": [],
        "environment": environment,
    }
    with pytest.raises(ValueError, match="^RUNNER_ENVIRONMENT_UNSUPPORTED$"):
        adapter.command(request)


def test_explicit_host_environment_is_the_only_host_alias(adapter, tmp_path, monkeypatch) -> None:
    tool = tmp_path.parent / "outside-node"
    monkeypatch.setattr(adapter.shutil, "which", lambda *a, **kw: str(tool))
    request = {
        "schema_version": adapter.PROTOCOL,
        "language": "javascript",
        "root": str(tmp_path),
        "entry": "main.js",
        "arguments": [],
        "environment": "host",
    }
    assert adapter.command(request)["argv"] == [str(tool.resolve()), str(tmp_path / "main.js")]


def test_sqlite_cannot_attach_host_database(adapter, tmp_path) -> None:
    (tmp_path / "main.sql").write_text("ATTACH DATABASE 'should-not-exist.db' AS other;", encoding="utf-8")
    response = adapter.command({"schema_version": adapter.PROTOCOL, "language": "sql",
        "root": str(tmp_path), "entry": "main.sql", "arguments": []})
    result = subprocess.run(response["argv"], cwd=tmp_path, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert not (tmp_path / "should-not-exist.db").exists()
