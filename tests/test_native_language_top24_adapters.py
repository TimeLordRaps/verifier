"""Top-24 native adapters: C#, Go, R, Swift and Julia.

Invocation shape, hostile arguments, exact missing-toolchain tokens, dialect
rejection and the compiled build plans need no toolchain: the worker source is
executed with a recorded ``subprocess.run``. Real specimens run only when their
toolchain is installed, and they are classified skips otherwise, never PASS.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from verifier.runtime import language_runners as core

TOP24 = {
    "csharp": (".cs", "dotnet"),
    "go": (".go", "go"),
    "r": (".r", "Rscript"),
    "swift": (".swift", "swiftc"),
    "julia": (".jl", "julia"),
}
COMPILED = {"csharp", "go", "swift"}
HOSTILE = ["--version", "; echo no-shell", "$(touch hostile)", "--argument=--x"]


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "extensions/languages/src"))
    import vstd_languages
    return vstd_languages


def _resolved(tool: str) -> str:
    return str(Path(f"/opt/fake-toolchain/{tool}").resolve())


def _fake_which(tool: str):
    """Resolve only the named tool, so the host PATH cannot change the expectation."""
    return lambda name, path=None: f"/opt/fake-toolchain/{name}" if name == tool else None


def _request(adapter, language: str, root: Path, entry: str, arguments: list[str]) -> dict:
    return {"schema_version": adapter.PROTOCOL, "language": language, "root": str(root),
            "entry": entry, "arguments": arguments}


def _worker(adapter, monkeypatch, language, tool, entry, args, codes=()):
    """Run the worker source in-process; every subprocess call is recorded, none is run."""
    calls, seen = [], {}

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if list(argv[1:2]) == ["build"] and str(argv[2]).endswith(".csproj"):
            base = Path(argv[2]).parent
            seen["csproj"] = (base / "subject.csproj").read_text(encoding="utf-8")
            seen["source"] = (base / "subject.cs").read_text(encoding="utf-8")
        index = len(calls) - 1
        code = codes[index] if index < len(codes) else 0
        stdout = b"10.0.100\n" if list(argv[1:]) == ["--version"] else b""
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["-c", language, tool, entry, *args])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-worker>", "exec"), {"__name__": "__main__"})
    return calls, stopped.value.code, seen


def _runner_args(**overrides) -> argparse.Namespace:
    values = dict(runner_command="plan", entry="main.cs", root=".", language="python",
                  object_kind="OBJECT", activity="check", continuity_required=False,
                  sandbox="none", sandbox_config=None, input=[], trusted_local=True,
                  timeout=60, argument=[])
    values.update(overrides)
    return argparse.Namespace(**values)


def _find_key(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for item in value.values():
            found = _find_key(item, key)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = _find_key(item, key)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize("language", sorted(TOP24))
def test_adapter_declares_exact_suffix_and_tool(adapter, language) -> None:
    suffix, tool = TOP24[language]
    assert adapter.SUFFIXES[language] == {suffix}
    assert adapter.TOOLS[language] == tool


@pytest.mark.parametrize("language", sorted(TOP24))
def test_core_detection_is_exact_for_each_top24_suffix(tmp_path, language) -> None:
    suffix, _ = TOP24[language]
    (tmp_path / f"subject{suffix}").write_text("x", encoding="utf-8")
    report = core.detect_languages(tmp_path)
    assert report["languages"] == {language: 1}
    assert report["ambiguous_file_count"] == 0


@pytest.mark.parametrize("language", sorted(TOP24))
def test_core_catalog_marks_each_top24_target_extension_available(language) -> None:
    rows = {row["language"]: row for row in core.language_catalog()["languages"]}
    assert rows[language]["cohort"] == "top24-extension-target"
    assert rows[language]["runner_status"] == "EXTENSION_AVAILABLE"
    assert rows[language]["qualification"] == "NOT_ESTABLISHED"


def test_core_discovers_each_top24_name_as_the_static_extension(adapter) -> None:
    extensions = {item.name: item for item in core._extensions()}
    for language in TOP24:
        assert language in extensions
        assert extensions[language].load() is adapter.command


def test_core_explicit_selection_must_match_the_suffix(adapter, tmp_path) -> None:
    (tmp_path / "main.cs").write_text("x", encoding="utf-8")
    matching = core.assess_runner(_runner_args(root=str(tmp_path), entry="main.cs", language="csharp"))
    assert matching["blockers"] == []
    assert matching["extension_status"] == "INSTALLED_NOT_LOADED"
    differing = core.assess_runner(_runner_args(root=str(tmp_path), entry="main.cs", language="go"))
    assert differing["status"] == "FAIL"
    assert differing["blockers"] == ["RUNNER_LANGUAGE_SELECTION_DIFFERS"]


@pytest.mark.parametrize("language", sorted(TOP24))
def test_wrong_suffix_is_rejected_as_dialect_unsupported(adapter, tmp_path, monkeypatch, language) -> None:
    monkeypatch.setattr(adapter.shutil, "which", _fake_which(TOP24[language][1]))
    other = next(suffix for name, (suffix, _) in TOP24.items() if name != language)
    with pytest.raises(ValueError, match="RUNNER_DIALECT_UNSUPPORTED"):
        adapter.command(_request(adapter, language, tmp_path, f"main{other}", []))


def test_r_suffix_match_is_case_insensitive_like_detection(adapter, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(adapter.shutil, "which", _fake_which("Rscript"))
    response = adapter.command(_request(adapter, "r", tmp_path, "MAIN.R", []))
    assert response["argv"] == [_resolved("Rscript"), "--vanilla", str(tmp_path / "MAIN.R")]


def test_r_invocation_is_vanilla_and_passes_hostile_arguments_verbatim(adapter, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(adapter.shutil, "which", _fake_which("Rscript"))
    response = adapter.command(_request(adapter, "r", tmp_path, "main.r", HOSTILE))
    assert response == {"schema_version": adapter.PROTOCOL, "language": "r",
                        "argv": [_resolved("Rscript"), "--vanilla", str(tmp_path / "main.r"), *HOSTILE]}


def test_julia_invocation_disables_startup_and_history_and_passes_arguments_verbatim(
        adapter, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(adapter.shutil, "which", _fake_which("julia"))
    response = adapter.command(_request(adapter, "julia", tmp_path, "main.jl", HOSTILE))
    assert response["argv"] == [_resolved("julia"), "--startup-file=no", "--history-file=no",
                                "--non-interactive", "--", str(tmp_path / "main.jl"), *HOSTILE]


@pytest.mark.parametrize("language", sorted(COMPILED))
def test_compiled_adapters_route_through_the_bounded_worker_only(adapter, tmp_path, monkeypatch, language) -> None:
    suffix, tool = TOP24[language]
    monkeypatch.setattr(adapter.shutil, "which", _fake_which(tool))
    response = adapter.command(_request(adapter, language, tmp_path, f"main{suffix}", HOSTILE))
    argv = response["argv"]
    assert argv[:4] == [sys.executable, "-I", "-B", "-c"]
    assert argv[4] == adapter.WORKER
    assert argv[5:8] == [language, _resolved(tool), str(tmp_path / f"main{suffix}")]
    assert argv[8:] == HOSTILE


@pytest.mark.parametrize("language", sorted(TOP24))
def test_missing_toolchain_fails_closed_with_exact_token(adapter, tmp_path, monkeypatch, language) -> None:
    suffix, tool = TOP24[language]
    (tmp_path / f"main{suffix}").write_text("", encoding="utf-8")
    monkeypatch.setattr(adapter.shutil, "which", lambda *a, **kw: None)
    with pytest.raises(FileNotFoundError) as refused:
        adapter.command(_request(adapter, language, tmp_path, f"main{suffix}", []))
    assert str(refused.value) == f"RUNNER_TOOLCHAIN_MISSING:{tool}"


def test_missing_toolchain_never_falls_back_to_another_runner(adapter, tmp_path, monkeypatch) -> None:
    present = {"python", "python3", "node", "perl", "gcc", "php"}
    monkeypatch.setattr(adapter.shutil, "which",
                        lambda name, path=None: f"/usr/bin/{name}" if name in present else None)
    for language, (suffix, tool) in TOP24.items():
        with pytest.raises(FileNotFoundError, match=f"^RUNNER_TOOLCHAIN_MISSING:{tool}$"):
            adapter.command(_request(adapter, language, tmp_path, f"main{suffix}", []))


def test_go_worker_builds_with_modules_disabled_and_runs_the_artifact(adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.go"
    entry.write_text("package main", encoding="utf-8")
    calls, code, _ = _worker(adapter, monkeypatch, "go", "/opt/go/bin/go", str(entry), HOSTILE)
    (build, build_kwargs), (run, run_kwargs) = calls
    target = build[3]
    assert build == ["/opt/go/bin/go", "build", "-o", target, str(entry)]
    assert Path(target).name == ("subject.exe" if os.name == "nt" else "subject")
    assert Path(target).parent.name.startswith("vstd-compile-")
    assert build_kwargs.get("shell", False) is False
    env = build_kwargs["env"]
    assert {key: env[key] for key in ("GO111MODULE", "GOTOOLCHAIN", "GOPROXY", "GOWORK", "CGO_ENABLED", "GOFLAGS")} == {
        "GO111MODULE": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
        "GOWORK": "off", "CGO_ENABLED": "0", "GOFLAGS": ""}
    assert run == [target, *HOSTILE]
    assert run_kwargs.get("shell", False) is False
    assert code == 0


def test_go_compile_failure_stops_before_running_and_keeps_the_code(adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.go"
    entry.write_text("not go", encoding="utf-8")
    calls, code, _ = _worker(adapter, monkeypatch, "go", "/opt/go/bin/go", str(entry), [], codes=(2,))
    assert len(calls) == 1
    assert code == 2


def test_csharp_worker_uses_a_temporary_project_without_network_and_runs_the_apphost(
        adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.cs"
    entry.write_text("class Main {}", encoding="utf-8")
    calls, code, seen = _worker(adapter, monkeypatch, "csharp", "/opt/dotnet/dotnet", str(entry), ["--flag"])
    version, (build, build_kwargs), (run, _) = calls
    assert version[0] == ["/opt/dotnet/dotnet", "--version"]
    assert build[:2] == ["/opt/dotnet/dotnet", "build"]
    project = Path(build[2])
    assert project.name == "subject.csproj"
    assert build[3:] == ["--nologo", "-o", str(project.parent / "out")]
    root = ET.fromstring(seen["csproj"])
    properties = {child.tag: child.text for child in root.find("PropertyGroup")}
    assert properties["TargetFramework"] == "net10.0"
    assert properties["OutputType"] == "Exe"
    assert properties["AssemblyName"] == "subject"
    assert properties["NuGetAudit"] == "false"
    assert seen["source"] == "class Main {}"
    env = build_kwargs["env"]
    assert env["DOTNET_NOLOGO"] == "1" and env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert env["MSBUILDDISABLENODEREUSE"] == "1"
    assert env["NUGET_PACKAGES"].startswith(str(project.parent))
    name = "subject.exe" if os.name == "nt" else "subject"
    assert run == [str(project.parent / "out" / name), "--flag"]
    assert code == 0


def test_csharp_build_failure_stops_before_running(adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.cs"
    entry.write_text("not c#", encoding="utf-8")
    calls, code, _ = _worker(adapter, monkeypatch, "csharp", "/opt/dotnet/dotnet", str(entry), [], codes=(0, 1))
    assert len(calls) == 2
    assert code == 1


def test_swift_worker_compiles_with_swiftc_and_runs_the_artifact(adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.swift"
    entry.write_text('print("native-42")', encoding="utf-8")
    calls, code, _ = _worker(adapter, monkeypatch, "swift", "/opt/swift/swiftc", str(entry), HOSTILE)
    (build, build_kwargs), (run, _) = calls
    target = build[2]
    assert build == ["/opt/swift/swiftc", "-o", target, str(entry)]
    assert Path(target).parent.name.startswith("vstd-compile-")
    assert build_kwargs.get("shell", False) is False
    assert run == [target, *HOSTILE]
    assert code == 0


def test_swift_compile_failure_is_returned_without_running(adapter, tmp_path, monkeypatch) -> None:
    entry = tmp_path / "main.swift"
    entry.write_text("not swift", encoding="utf-8")
    calls, code, _ = _worker(adapter, monkeypatch, "swift", "/opt/swift/swiftc", str(entry), [], codes=(1,))
    assert len(calls) == 1
    assert code == 1


def test_core_capture_snippets_are_bounded_on_the_shared_runner_path(tmp_path) -> None:
    (tmp_path / "noisy.py").write_text(
        "import sys\nsys.stdout.write('x' * 20000)\nsys.stderr.write('e' * 20000)\n", encoding="utf-8")
    report = core.assess_runner(_runner_args(runner_command="run", root=str(tmp_path), entry="noisy.py",
                                             language="python"))
    assert report["status"] == "PASS"
    stdout_snippet = _find_key(report["receipt"], "stdout_snippet")
    stderr_snippet = _find_key(report["receipt"], "stderr_snippet")
    assert stdout_snippet is not None and len(stdout_snippet) <= 4000
    assert stderr_snippet is not None and len(stderr_snippet) <= 4000
    assert _find_key(report["receipt"], "stdout_sha256") is not None


EXIT_SPECIMENS = {
    "csharp": ("Exit.cs", 'class Exit { static void Main() { System.Console.WriteLine("native-42"); '
                          'System.Environment.Exit(3); } }'),
    "go": ("exit.go", 'package main\n\nimport (\n\t"fmt"\n\t"os"\n)\n\nfunc main() {\n\t'
                      'fmt.Println("native-42")\n\tos.Exit(3)\n}\n'),
    "r": ("exit.r", 'cat("native-42\\n")\nquit(status = 3)\n'),
    "swift": ("exit.swift", 'import Foundation\nprint("native-42")\nexit(3)\n'),
    "julia": ("exit.jl", 'println("native-42")\nexit(3)\n'),
}


@pytest.mark.parametrize("language", sorted(EXIT_SPECIMENS))
def test_runtime_nonzero_exit_is_propagated_and_not_a_pass(adapter, tmp_path, language) -> None:
    name, source = EXIT_SPECIMENS[language]
    tool = TOP24[language][1]
    if language in COMPILED and os.environ.get("VSTD_RUN_NATIVE_TOOLCHAINS") != "1":
        pytest.skip("NATIVE_TOOLCHAIN_NOT_AUTHORIZED: set VSTD_RUN_NATIVE_TOOLCHAINS=1 "
                    "to compile isolated temporary fixtures")
    if shutil.which(tool) is None:
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: explicitly selected native toolchain " + tool)
    (tmp_path / name).write_text(source, encoding="utf-8")
    response = adapter.command(_request(adapter, language, tmp_path, name, []))
    result = subprocess.run(response["argv"], cwd=tmp_path, capture_output=True, timeout=300)
    assert result.returncode == 3, result.stderr.decode(errors="replace")
    assert b"native-42" in result.stdout


# Worker stderr tokens: core reads only exit codes from a worker, so a token can become a blocker only
# when a ValueError raised by the package carries it. This guard pins which tokens the workers may print.
WORKER_TOKEN = re.compile(r"\b(RUNNER_[A-Z][A-Z0-9_]*|VSTD_EXTENSION_[A-Z_]+)\b")
EXTENSION_TOKENS = {"VSTD_EXTENSION_TIMEOUT", "VSTD_EXTENSION_OUTPUT_LIMIT"}


def test_worker_tokens_are_core_codes_or_the_two_extension_codes_core_never_admits(adapter) -> None:
    import vstd_languages.extended_batch_three as batch_three
    import vstd_languages.extended_batch_two as batch_two

    literals: set[str] = set()
    for module in (adapter, batch_two, batch_three):
        literals |= set(WORKER_TOKEN.findall(module.WORKER))
    assert {token for token in literals if token.startswith("VSTD_EXTENSION_")} == EXTENSION_TOKENS
    runner_tokens = {token for token in literals if token.startswith("RUNNER_")}
    assert runner_tokens <= core._BLOCKER_CODES | {"RUNNER_TOOLCHAIN_MISSING"}
    assert EXTENSION_TOKENS.isdisjoint(core._BLOCKER_CODES)
