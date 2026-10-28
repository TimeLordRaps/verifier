"""Batch-two native adapters: COBOL, Object Pascal, Ada, Objective-C and Assembly.

The adapter module is loaded by file path so these checks stay independent of the
package ``__init__``; package dispatch is covered by
``test_native_language_package_dispatch_batch_two.py``. Invocation shape, hostile paths and arguments,
exact missing-toolchain tokens and bounded worker outcomes run against a recorded
``subprocess.Popen``; no compiler is started. Real specimens run only when their
toolchain is installed and are classified skips otherwise, never PASS.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "extensions/languages/src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from vstd_languages import extended_batch_two

MODULE = SOURCE / "vstd_languages/extended_batch_two.py"

NAMES = ("cobol", "object-pascal", "ada", "objective-c", "assembly")
TOOLS = {"cobol": "cobc", "object-pascal": "fpc", "ada": "gnatmake", "objective-c": "clang", "assembly": "gcc"}
SUFFIXES = {"cobol": {".cob", ".cbl"}, "object-pascal": {".pas", ".pp"}, "ada": {".adb"},
            "objective-c": {".m"}, "assembly": {".s"}}
SPECIMENS = {
    "cobol": ("specimen.cob", "        IDENTIFICATION DIVISION.\n        PROGRAM-ID. SPECIMEN.\n"
              "        PROCEDURE DIVISION.\n            DISPLAY \"ok\".\n            STOP RUN.\n", b"ok\n", 0),
    "object-pascal": ("specimen.pas", "program specimen;\nbegin\n  writeln('ok');\nend.\n", b"ok\n", 0),
    "ada": ("specimen.adb", "with Ada.Text_IO;\nprocedure Specimen is\nbegin\n"
            "   Ada.Text_IO.Put_Line (\"ok\");\nend Specimen;\n", b"ok\n", 0),
    "objective-c": ("specimen.m", "#include <stdio.h>\nint main(void) { puts(\"ok\"); return 7; }\n", b"ok\n", 7),
    "assembly": ("specimen.s", "    .text\n    .globl main\nmain:\n    movl $42, %eax\n    ret\n", b"", 42),
}


@pytest.fixture
def adapter():
    return extended_batch_two


class _FakeProcess:
    def __init__(self, code):
        self.code = code
        self.returncode = code
        self.killed = False

    def poll(self):
        return self.code

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return self.code


def _worker(adapter, monkeypatch, language, tool, entry, args, codes=(), writes=None, source=None):
    """Run the worker source in-process; every Popen is recorded and none is started."""
    calls, procs = [], []

    def fake_popen(argv, **kwargs):
        index = len(calls)
        calls.append((list(argv), kwargs))
        code = codes[index] if index < len(codes) else 0
        if writes and index in writes:
            kwargs["stdout"].write(b"x" * writes[index])
            kwargs["stdout"].flush()
        proc = _FakeProcess(code)
        procs.append(proc)
        return proc

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sys, "argv", ["-c", language, tool, entry, *args])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(source or adapter.WORKER, "<vstd-batch-two-worker>", "exec"), {"__name__": "__main__"})
    return calls, procs, stopped.value.code


def _request(adapter, language, root, entry, arguments=()):
    return {"schema_version": adapter.PROTOCOL, "language": language, "root": str(root),
            "entry": entry, "arguments": list(arguments)}


def _fake_which(tool):
    """Resolve only the named tool so the host PATH cannot change the expectation."""
    return lambda name, path=None: f"/opt/fake-toolchain/{name}" if name == tool else None


def _expected_build(language, target, directory, entry):
    tool = TOOLS[language]
    return {
        "cobol": [tool, "-x", "-o", target, entry],
        "object-pascal": [tool, "-n", "-Mobjfpc", f"-FU{directory}", f"-FE{directory}", f"-o{target}", entry],
        "ada": [tool, "-D", directory, "-o", target, entry],
        "objective-c": [tool, "-x", "objective-c", "-o", target, entry],
        "assembly": [tool, "-x", "assembler", "-o", target, entry],
    }[language]


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    entry = root / "main.src"
    entry.write_text("placeholder\n", encoding="utf-8")
    return root


# --- registry shape ---------------------------------------------------------

def test_names_tools_and_suffixes_are_closed(adapter):
    assert set(adapter.LANGUAGES) == set(NAMES)
    assert adapter.PROTOCOL == "verifier-language-runner-1"
    for name in NAMES:
        assert adapter.LANGUAGES[name]["tool"] == TOOLS[name]
        assert set(adapter.LANGUAGES[name]["suffixes"]) == SUFFIXES[name]
        assert adapter.LANGUAGES[name]["dialect"]


# --- command surface: invocation shape and hostile inputs ------------------

@pytest.mark.parametrize("language", NAMES)
def test_command_invocation_shape(adapter, monkeypatch, tmp_path, language):
    root = tmp_path / "root"
    root.mkdir()
    name, _, _, _ = SPECIMENS[language]
    (root / name).write_text("x\n", encoding="utf-8")
    tool = TOOLS[language]
    monkeypatch.setattr(shutil, "which", _fake_which(tool))
    result = adapter.command(_request(adapter, language, root, name, ["--run", "a b"]))
    resolved = str(Path(f"/opt/fake-toolchain/{tool}").resolve())
    assert set(result) == {"schema_version", "language", "argv"}
    assert result["schema_version"] == adapter.PROTOCOL
    assert result["language"] == language
    argv = result["argv"]
    assert argv[0] == sys.executable
    assert argv[1:4] == ["-I", "-B", "-c"]
    assert argv[4] == adapter.WORKER
    assert argv[5:7] == [language, resolved]
    assert argv[7] == str((root / name).resolve())
    assert argv[8:] == ["--run", "a b"]


@pytest.mark.parametrize("language", NAMES)
def test_missing_toolchain_is_exact_and_never_falls_back(adapter, monkeypatch, project, language):
    tool = TOOLS[language]
    name, _, _, _ = SPECIMENS[language]
    (project / name).write_text("x\n", encoding="utf-8")
    seen = []

    def no_tool(tool_name, path=None):
        seen.append((tool_name, path))
        return None

    monkeypatch.setattr(shutil, "which", no_tool)
    with pytest.raises(FileNotFoundError) as missing:
        adapter.command(_request(adapter, language, project, name))
    assert str(missing.value) == f"RUNNER_TOOLCHAIN_MISSING:{tool}"
    assert [name for name, _ in seen] == [tool]


def test_toolchain_lookup_excludes_the_subject_directory(adapter, monkeypatch, project):
    (project / "specimen.cob").write_text("x\n", encoding="utf-8")
    seen = {}

    def record(tool_name, path=None):
        seen["path"] = path
        return None

    monkeypatch.setattr(shutil, "which", record)
    with pytest.raises(FileNotFoundError):
        adapter.command(_request(adapter, "cobol", project, "specimen.cob"))
    resolved_root = project.resolve()
    assert all(Path(entry).resolve() != resolved_root for entry in seen["path"].split(os.pathsep) if entry)


@pytest.mark.parametrize("entry", [
    "../escape.cob", "sub/../../escape.cob", "-o.cob", "name\x00.cob", "missing.cob", "C:evil.cob",
])
def test_hostile_entry_paths_are_rejected(adapter, monkeypatch, tmp_path, project, entry):
    (tmp_path / "escape.cob").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("cobc"))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "cobol", project, entry))


def test_absolute_entry_outside_root_is_rejected(adapter, monkeypatch, tmp_path, project):
    outside = tmp_path / "outside.cob"
    outside.write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("cobc"))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "cobol", project, str(outside)))


def test_symlink_escape_is_rejected(adapter, monkeypatch, tmp_path, project):
    outside = tmp_path / "outside.s"
    outside.write_text("    .text\n", encoding="utf-8")
    link = project / "link.s"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation needs privileges on this host; escape check not exercised")
    monkeypatch.setattr(shutil, "which", _fake_which("gcc"))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "assembly", project, "link.s"))


@pytest.mark.parametrize("language,entry", [
    ("cobol", "specimen.cbl.txt"), ("object-pascal", "specimen.adb"), ("ada", "specimen.m"),
    ("objective-c", "specimen.s"), ("assembly", "specimen.asm"),
])
def test_dialect_suffix_mismatch_is_rejected(adapter, monkeypatch, project, language, entry):
    (project / entry).write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError, match="RUNNER_DIALECT_UNSUPPORTED"):
        adapter.command(_request(adapter, language, project, entry))


def test_hostile_arguments_are_one_argv_each_and_bounded(adapter, monkeypatch, project):
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("gcc"))
    hostile = ["--version", "; echo no-shell", "$(touch hostile)", "--argument=--x", "a b"]
    result = adapter.command(_request(adapter, "assembly", project, "specimen.s", hostile))
    assert result["argv"][8:] == hostile
    assert "shell" not in result
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "assembly", project, "specimen.s", ["a\x00b"]))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "assembly", project, "specimen.s", ["x"] * (adapter.MAX_ARGUMENTS + 1)))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, "assembly", project, "specimen.s", ["x" * (adapter.MAX_ARGUMENT_BYTES + 1)]))


@pytest.mark.parametrize("mutation,message", [
    ({"language": "fortran"}, "RUNNER_LANGUAGE_UNSUPPORTED"),
    ({"schema_version": "other"}, "RUNNER_EXTENSION_PROTOCOL_DIFFERS"),
    ({"environment": "container"}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
])
def test_closed_request_surface(adapter, monkeypatch, project, mutation, message):
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("gcc"))
    request = {**_request(adapter, "assembly", project, "specimen.s"), **mutation}
    with pytest.raises(ValueError, match=message):
        adapter.command(request)


# --- worker: build plans, bounded runs, exit mapping (recorded Popen) ------

@pytest.mark.parametrize("language", NAMES)
def test_worker_build_then_run_shape_and_cleanup(adapter, monkeypatch, project, language):
    tool = TOOLS[language]
    name, _, _, _ = SPECIMENS[language]
    entry = str((project / name).resolve())
    (project / name).write_text("x\n", encoding="utf-8")
    calls, procs, code = _worker(adapter, monkeypatch, language, tool, entry, ["--flag", "v"], codes=[0, 5])
    assert code == 5
    assert len(calls) == 2
    build_argv, build_kwargs = calls[0]
    directory = build_kwargs["cwd"]
    target = str(Path(directory) / ("subject.exe" if os.name == "nt" else "subject"))
    assert build_argv == _expected_build(language, target, directory, entry)
    run_argv, run_kwargs = calls[1]
    assert run_argv == [target, "--flag", "v"]
    for _, kwargs in calls:
        assert kwargs.get("shell", False) is False
        assert kwargs["stdin"] == subprocess.DEVNULL
    assert not Path(directory).exists()


@pytest.mark.parametrize("language", NAMES)
def test_worker_nonzero_compiler_stops_before_run(adapter, monkeypatch, project, language):
    entry = str(project / "main.src")
    calls, procs, code = _worker(adapter, monkeypatch, language, TOOLS[language], entry, [], codes=[2])
    assert code == 2
    assert len(calls) == 1


def test_worker_nonzero_runtime_exit_is_preserved(adapter, monkeypatch, project):
    calls, procs, code = _worker(adapter, monkeypatch, "ada", "gnatmake", str(project / "main.src"), [], codes=[0, 3])
    assert code == 3
    assert len(calls) == 2


def test_worker_signal_exit_maps_to_shell_convention(adapter, monkeypatch, project):
    calls, procs, code = _worker(adapter, monkeypatch, "assembly", "gcc", str(project / "main.src"), [], codes=[0, -11])
    assert code == 139


def test_worker_compile_timeout_kills_owned_child(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("COMPILE_SECONDS = 120", "COMPILE_SECONDS = 0.2")
    assert source != adapter.WORKER
    calls, procs, code = _worker(adapter, monkeypatch, "cobol", "cobc", str(project / "main.src"), [],
                                 codes=[None], source=source)
    assert code == 124
    assert len(calls) == 1
    assert procs[0].killed


def test_worker_run_timeout_kills_owned_child_and_reports_124(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("RUN_SECONDS = 60", "RUN_SECONDS = 0.2")
    assert source != adapter.WORKER
    calls, procs, code = _worker(adapter, monkeypatch, "ada", "gnatmake", str(project / "main.src"), [],
                                 codes=[0, None], source=source)
    assert code == 124
    assert len(calls) == 2
    assert procs[1].killed


def test_worker_run_output_over_cap_is_refused(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 16")
    assert source != adapter.WORKER
    calls, procs, code = _worker(adapter, monkeypatch, "ada", "gnatmake", str(project / "main.src"), [],
                                 codes=[0, 0], writes={1: 64}, source=source)
    assert code == 125
    assert len(calls) == 2


def test_worker_rejects_unknown_language_before_any_process(adapter, monkeypatch, capsys, project):
    calls, procs, code = _worker(adapter, monkeypatch, "fortran", "gfortran", str(project / "main.src"), [])
    assert code == 1
    assert calls == []
    assert "RUNNER_DIALECT_UNSUPPORTED" in capsys.readouterr().err


# --- real specimens: classified skips when the toolchain is absent --------

@pytest.mark.parametrize("language", NAMES)
def test_real_specimen_end_to_end(adapter, monkeypatch, project, language):
    name, body, expected_stdout, expected_code = SPECIMENS[language]
    (project / name).write_text(body, encoding="utf-8")
    tool = TOOLS[language]
    if shutil.which(tool) is None:
        pytest.skip(f"RUNNER_TOOLCHAIN_MISSING:{tool} (classified skip; not a PASS)")
    before = sorted(os.listdir(project))
    result = adapter.command(_request(adapter, language, project, name))
    completed = subprocess.run(result["argv"], capture_output=True, timeout=300, shell=False, cwd=str(project))
    assert completed.returncode == expected_code, completed.stderr.decode("utf-8", errors="replace")
    assert completed.stdout == expected_stdout
    assert sorted(os.listdir(project)) == before


def test_real_assembly_compile_failure_is_nonzero_and_leaves_no_artifact(adapter, project):
    if shutil.which("gcc") is None:
        pytest.skip("RUNNER_TOOLCHAIN_MISSING:gcc (classified skip; not a PASS)")
    (project / "broken.s").write_text("    .text\n    notamnemonic %eax\n", encoding="utf-8")
    before = sorted(os.listdir(project))
    result = adapter.command(_request(adapter, "assembly", project, "broken.s"))
    completed = subprocess.run(result["argv"], capture_output=True, timeout=300, shell=False, cwd=str(project))
    assert completed.returncode != 0
    assert sorted(os.listdir(project)) == before


# --- normalized worker tokens, exit codes and cleanup (RED-first residuals) ----

_TIMEOUT_TOKEN = "VSTD_EXTENSION_TIMEOUT:compile cleanup=UNKNOWN"


def _worker_namespace(adapter, monkeypatch, language, tool):
    """Define the worker's helpers without starting a compiler; the dialect refusal ends the module."""
    monkeypatch.setattr(sys, "argv", ["-c", language, tool, "entry"])
    namespace: dict[str, Any] = {"__name__": "__main__"}
    with pytest.raises(SystemExit):
        exec(compile(adapter.WORKER, "<vstd-batch-two-worker>", "exec"), namespace)
    return namespace


def _refusal(capsys, adapter, monkeypatch, language, tool, codes, source=None, writes=None):
    """Run the worker and return (exit code, stderr text) for one refused run."""
    entry = "placeholder.src"
    _, _, code = _worker(adapter, monkeypatch, language, tool, entry, [], codes=codes,
                         writes=writes, source=source)
    return code, capsys.readouterr().err


def test_compile_timeout_is_a_stable_extension_token_with_unknown_cleanup(adapter, monkeypatch, capsys, project):
    source = adapter.WORKER.replace("COMPILE_SECONDS = 120", "COMPILE_SECONDS = 0.2")
    code, err = _refusal(capsys, adapter, monkeypatch, "cobol", "cobc", [None], source=source)
    assert code == 124
    assert _TIMEOUT_TOKEN in err
    assert "Traceback" not in err


def test_run_output_cap_is_a_stable_extension_token(adapter, monkeypatch, capsys, project):
    source = adapter.WORKER.replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 16")
    code, err = _refusal(capsys, adapter, monkeypatch, "ada", "gnatmake", [0, 0], source=source, writes={1: 64})
    assert code == 125
    assert "VSTD_EXTENSION_OUTPUT_LIMIT:run cleanup=UNKNOWN" in err


def test_missing_compiler_at_spawn_is_the_toolchain_token_not_a_traceback(adapter, monkeypatch, capsys, project):
    def missing(argv, **kwargs):
        raise FileNotFoundError(2, "No such file", argv[0])

    monkeypatch.setattr(subprocess, "Popen", missing)
    monkeypatch.setattr(sys, "argv", ["-c", "cobol", "cobc", str(project / "main.src")])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-batch-two-worker>", "exec"), {"__name__": "__main__"})
    assert stopped.value.code == 127
    assert "RUNNER_TOOLCHAIN_MISSING:cobc" in capsys.readouterr().err


def test_artifact_that_cannot_start_is_the_resource_token(adapter, monkeypatch, capsys, project):
    calls = []

    def popen(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 2:
            raise PermissionError(13, "Permission denied", argv[0])
        return _FakeProcess(0)

    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(sys, "argv", ["-c", "ada", "gnatmake", str(project / "main.src")])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-batch-two-worker>", "exec"), {"__name__": "__main__"})
    assert stopped.value.code == 126
    assert "RUNNER_RESOURCE_UNAVAILABLE:run" in capsys.readouterr().err
    assert len(calls) == 2


def test_dialect_refusal_is_one_token_and_exit_one(adapter, monkeypatch, capsys, project):
    calls, procs, code = _worker(adapter, monkeypatch, "fortran", "gfortran", str(project / "main.src"), [])
    assert code == 1
    assert calls == []
    assert "RUNNER_DIALECT_UNSUPPORTED" in capsys.readouterr().err


def test_host_environment_declaration_is_accepted(adapter, monkeypatch, project):
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("gcc"))
    request = {**_request(adapter, "assembly", project, "specimen.s"), "environment": "host"}
    assert adapter.command(request)["language"] == "assembly"


@pytest.mark.parametrize("environment", [None, "container", {"PATH": "/opt/evil"}])
def test_any_other_environment_declaration_is_refused_before_lookup(adapter, monkeypatch, project, environment):
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("lookup before environment check"))
    request = {**_request(adapter, "assembly", project, "specimen.s"), "environment": environment}
    with pytest.raises(ValueError, match="^RUNNER_ENVIRONMENT_UNSUPPORTED$"):
        adapter.command(request)


@pytest.mark.parametrize("language", NAMES)
def test_sandbox_linux_constructs_bounded_remote_worker_without_host_lookup(
    adapter, monkeypatch, language
):
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("host lookup"))
    entry = next(iter(SUFFIXES[language]))
    request = {
        "schema_version": adapter.PROTOCOL,
        "language": language,
        "root": "/sandbox/source",
        "entry": "nested/subject" + entry,
        "arguments": ["; echo no-shell", "a b"],
        "environment": "sandbox-linux",
    }
    response = adapter.command(request)
    assert response["argv"][:4] == ["python3", "-I", "-B", "-c"]
    assert response["argv"][4] == adapter.WORKER
    assert response["argv"][5:8] == [
        language,
        TOOLS[language],
        "/sandbox/source/nested/subject" + entry,
    ]
    assert response["argv"][8:] == ["; echo no-shell", "a b"]


@pytest.mark.parametrize("entry", ["../escape.s", "/absolute.s", "nested\\escape.s", "-option.s"])
def test_sandbox_linux_rejects_entry_escape_before_host_lookup(adapter, monkeypatch, entry):
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("host lookup"))
    with pytest.raises(ValueError):
        adapter.command({
            "schema_version": adapter.PROTOCOL,
            "language": "assembly",
            "root": "/sandbox/source",
            "entry": entry,
            "arguments": [],
            "environment": "sandbox-linux",
        })


@pytest.mark.skipif(os.name != "nt", reason="the deadline tree kill evidence is the Windows taskkill path")
def test_deadline_tree_kill_stops_a_live_grandchild_on_windows(adapter, monkeypatch, tmp_path):
    beat, pid_file = tmp_path / "beat.txt", tmp_path / "pid.txt"
    grandchild = (f"import os, pathlib, time\n"
                  f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                  f"p = pathlib.Path({str(beat)!r})\n"
                  "while True:\n    with p.open('a') as h: h.write('x')\n    time.sleep(0.05)\n")
    driver = ("import subprocess, sys, time\n"
              f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\ntime.sleep(120)\n")
    namespace = _worker_namespace(adapter, monkeypatch, "fortran", "unused")
    bounded = namespace["bounded"]
    try:
        status, _, _, _ = bounded([sys.executable, "-c", driver], str(tmp_path), 2)
        assert status == "TIMEOUT"
        assert beat.exists() and beat.stat().st_size > 0, "the grandchild never started; the check would prove nothing"
        size_at_return = beat.stat().st_size
        time.sleep(1.0)
        assert beat.stat().st_size == size_at_return, "a grandchild kept running after the deadline"
    finally:
        if pid_file.exists():
            subprocess.run(["taskkill", "/T", "/F", "/PID", pid_file.read_text(encoding="utf-8")],
                           capture_output=True, shell=False)
