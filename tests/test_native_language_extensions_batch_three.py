"""Batch-three native adapters: Visual Basic (.NET), Scratch, MATLAB, SAS and Classic Visual Basic.

Classic Visual Basic (VB6) is fail-closed NOT_ESTABLISHED: no verified noninteractive
compiler contract is available here, and cscript/VBScript is never substituted. Scratch
validation is a static closed ZIP archive format (ZIP) shape check and is never reported as execution. The
module is loaded by file path so the package ``__init__`` (edited elsewhere) is never
run. Recorded ``subprocess`` calls make invocation shape, hostile inputs, cleanup and
exit mapping checkable without starting a toolchain. Real specimens run only when their
tool is installed and are classified skips otherwise, never PASS.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any
import zipfile

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "extensions/languages/src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from vstd_languages import extended_batch_three

MODULE = SOURCE / "vstd_languages/extended_batch_three.py"

NAMES = ("visual-basic", "scratch", "matlab", "sas", "classic-visual-basic")
IMPLEMENTED = ("visual-basic", "scratch", "matlab", "sas")
TOOLS = {"visual-basic": "dotnet", "scratch": "scratch-vm-headless", "matlab": "matlab", "sas": "sas"}
SUFFIXES = {"visual-basic": {".vb"}, "scratch": {".sb3"}, "matlab": {".m"}, "sas": {".sas"},
            "classic-visual-basic": {".bas", ".frm", ".cls"}}
ENTRY = {"visual-basic": "main.vb", "scratch": "main.sb3", "matlab": "main.m", "sas": "main.sas",
         "classic-visual-basic": "main.bas"}
BODIES = {
    "visual-basic": 'Module Subject\n    Sub Main()\n        System.Console.WriteLine("ok")\n    End Sub\nEnd Module\n',
    "matlab": "disp('ok')\n",
    "sas": "data _null_;\n  put 'ok';\nrun;\n",
}
VALID_PROJECT = {"targets": [{"name": "Stage", "isStage": True, "blocks": {}}],
                 "monitors": [], "extensions": [], "meta": {"semver": "3.0.0"}}
ASSET = "0123456789abcdef0123456789abcdef.svg"
BACKSLASH = "\\"
# Built from pieces so no raw network-share literal appears in source text.
UNC_PREFIX = BACKSLASH * 2 + "server" + BACKSLASH + "share" + BACKSLASH


@pytest.fixture
def adapter():
    return extended_batch_three


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return root


class _FakeProcess:
    """Stands in for one child; ``hang`` makes the bounded wait expire before a kill."""

    def __init__(self, code, hang=False):
        self.code, self.hang = code, hang
        self.killed = False

    def wait(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("fake", timeout or 0)
        return -9 if self.killed else self.code

    def kill(self):
        self.killed = True


def _worker(adapter, monkeypatch, language, tool, entry, args, codes=(), hang=(), effects=None,
            sdk=b"10.0.100\n", source=None):
    """Run the worker source in-process. Every Popen is recorded and none is started.

    ``effects`` maps a child index to ``callable(argv, kwargs)`` that runs before that
    child "exits", so a test can inspect or write the private files the worker made.
    """
    calls, procs, run_calls = [], [], []

    def fake_popen(argv, **kwargs):
        index = len(calls)
        calls.append((list(argv), kwargs))
        if effects and index in effects:
            effects[index](list(argv), kwargs)
        proc = _FakeProcess(codes[index] if index < len(codes) else 0, hang=index in hang)
        procs.append(proc)
        return proc

    def fake_run(argv, **kwargs):
        run_calls.append((list(argv), kwargs))
        stdout = sdk if list(argv[1:]) == ["--version"] else b""
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["-c", language, tool, entry, *args])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(source or adapter.WORKER, "<vstd-batch-three-worker>", "exec"), {"__name__": "__main__"})
    return calls, procs, stopped.value.code, run_calls


def _request(adapter, language, root, entry, arguments=()):
    return {"schema_version": adapter.PROTOCOL, "language": language, "root": str(root),
            "entry": entry, "arguments": list(arguments)}


def _fake_which(tool):
    """Resolve only the named tool so the host PATH cannot change the expectation."""
    return lambda name, path=None: f"/opt/fake-toolchain/{name}" if name == tool else None


def _write_sb3(path, members=None, project_json=None):
    body = json.dumps(VALID_PROJECT if project_json is None else project_json)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("project.json", body)
        for name, data in (members if members is not None else [(ASSET, b"<svg/>")]):
            archive.writestr(name, data)
    return path


def _materialize(path, language):
    if language == "scratch":
        _write_sb3(path)
    else:
        path.write_text(BODIES.get(language, "x\n"), encoding="utf-8")
    return path


# --- registry shape ---------------------------------------------------------

def test_registry_is_closed_and_marks_classic_not_established(adapter):
    assert set(adapter.LANGUAGES) == set(NAMES)
    assert adapter.PROTOCOL == "verifier-language-runner-1"
    for name in NAMES:
        spec = adapter.LANGUAGES[name]
        assert set(spec["suffixes"]) == SUFFIXES[name]
        assert spec["dialect"]
        assert spec["tool"] == TOOLS.get(name)
        assert spec["status"] == ("IMPLEMENTED" if name in IMPLEMENTED else "NOT_ESTABLISHED")


# --- command surface: invocation shape --------------------------------------

@pytest.mark.parametrize("language", IMPLEMENTED)
def test_command_invocation_shape(adapter, monkeypatch, project, language):
    name = ENTRY[language]
    _materialize(project / name, language)
    tool = TOOLS[language]
    monkeypatch.setattr(shutil, "which", _fake_which(tool))
    arguments = ["--run", "a b"] if language == "visual-basic" else []
    result = adapter.command(_request(adapter, language, project, name, arguments))
    resolved = str(Path(f"/opt/fake-toolchain/{tool}").resolve())
    assert set(result) == {"schema_version", "language", "argv"}
    assert result["schema_version"] == adapter.PROTOCOL
    assert result["language"] == language
    argv = result["argv"]
    assert argv[0] == sys.executable
    assert argv[1:4] == ["-I", "-B", "-c"]
    assert argv[4:6] == [adapter.WORKER_LAUNCHER, adapter.WORKER_PAYLOAD]
    assert max(map(len, argv)) <= 8192
    assert argv[6:8] == [language, resolved]
    assert argv[8] == str((project / name).resolve())
    assert argv[9:] == arguments


@pytest.mark.parametrize("language", IMPLEMENTED)
def test_missing_toolchain_is_exact_and_never_falls_back(adapter, monkeypatch, project, language):
    name = ENTRY[language]
    _materialize(project / name, language)
    seen = []

    def no_tool(tool_name, path=None):
        seen.append(tool_name)
        return None

    monkeypatch.setattr(shutil, "which", no_tool)
    with pytest.raises(FileNotFoundError) as missing:
        adapter.command(_request(adapter, language, project, name))
    assert str(missing.value) == f"RUNNER_TOOLCHAIN_MISSING:{TOOLS[language]}"
    assert seen == [TOOLS[language]]


def test_scratch_never_falls_back_to_node(adapter, monkeypatch, project):
    _write_sb3(project / "main.sb3")
    monkeypatch.setattr(shutil, "which",
                        lambda tool, path=None: "/opt/fake-toolchain/node" if tool == "node" else None)
    with pytest.raises(FileNotFoundError) as missing:
        adapter.command(_request(adapter, "scratch", project, "main.sb3"))
    assert str(missing.value) == "RUNNER_TOOLCHAIN_MISSING:scratch-vm-headless"


def test_toolchain_lookup_excludes_the_subject_directory(adapter, monkeypatch, project):
    (project / "main.sas").write_text("x\n", encoding="utf-8")
    seen = {}

    def record(tool_name, path=None):
        seen["path"] = path
        return None

    monkeypatch.setattr(shutil, "which", record)
    with pytest.raises(FileNotFoundError):
        adapter.command(_request(adapter, "sas", project, "main.sas"))
    resolved_root = project.resolve()
    assert all(Path(entry).resolve() != resolved_root for entry in seen["path"].split(os.pathsep) if entry)


# --- classic Visual Basic: fail-closed, never substituted -------------------

@pytest.mark.parametrize("name", ["main.bas", "main.frm", "main.cls", "main.vb"])
def test_classic_visual_basic_is_not_established_and_never_substitutes(adapter, monkeypatch, project, name):
    (project / name).write_text('Attribute VB_Name = "Main"\n', encoding="utf-8")
    seen = []

    def every_tool(tool, path=None):
        seen.append(tool)
        return f"/opt/fake-toolchain/{tool}"

    monkeypatch.setattr(shutil, "which", every_tool)
    with pytest.raises(ValueError) as refused:
        adapter.command(_request(adapter, "classic-visual-basic", project, name))
    assert str(refused.value) == "RUNNER_LANGUAGE_UNSUPPORTED"
    assert seen == []


def test_classic_visual_basic_has_no_worker_route(adapter, monkeypatch, project, capsys):
    entry = project / "main.bas"
    entry.write_text('Attribute VB_Name = "Main"\n', encoding="utf-8")
    calls, procs, code, run_calls = _worker(adapter, monkeypatch, "classic-visual-basic", "cscript",
                                            str(entry.resolve()), [])
    assert code == 1
    assert "RUNNER_DIALECT_UNSUPPORTED" in capsys.readouterr().err
    assert calls == [] and run_calls == []


# --- hostile paths and dialects ---------------------------------------------

HOSTILE_TEMPLATES = ["../escape{s}", "sub/../../escape{s}", "..\\escape{s}", "-o{s}", "name\x00{s}",
                     "missing{s}", "C:evil{s}", UNC_PREFIX + "x{s}", "/abs/x{s}"]


@pytest.mark.parametrize("language", IMPLEMENTED)
@pytest.mark.parametrize("template", HOSTILE_TEMPLATES, ids=[
    "dotdot", "nested-dotdot", "backslash-dotdot", "dash-leading", "nul-byte", "missing",
    "drive-relative", "network-share", "rooted"])
def test_hostile_entry_paths_are_rejected(adapter, monkeypatch, tmp_path, project, language, template):
    suffix = sorted(SUFFIXES[language])[0]
    (tmp_path / f"escape{suffix}").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError):
        adapter.command(_request(adapter, language, project, template.format(s=suffix)))


@pytest.mark.parametrize("language", IMPLEMENTED)
def test_symlink_escape_is_rejected(adapter, monkeypatch, tmp_path, project, language):
    suffix = sorted(SUFFIXES[language])[0]
    outside = tmp_path / f"outside{suffix}"
    outside.write_text("x\n", encoding="utf-8")
    try:
        (project / f"link{suffix}").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation needs privileges on this host; escape check not exercised")
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError, match="RUNNER_ENTRY_OUTSIDE_ROOT"):
        adapter.command(_request(adapter, language, project, f"link{suffix}"))


@pytest.mark.parametrize("language,entry", [
    ("visual-basic", "main.cs"), ("visual-basic", "main.vb.txt"), ("scratch", "main.sb2"),
    ("matlab", "main.sas"), ("sas", "main.m"),
])
def test_dialect_suffix_mismatch_is_rejected(adapter, monkeypatch, project, language, entry):
    (project / entry).write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError, match="RUNNER_DIALECT_UNSUPPORTED"):
        adapter.command(_request(adapter, language, project, entry))


# --- hostile arguments -------------------------------------------------------

def test_visual_basic_arguments_are_one_argv_each_and_bounded(adapter, monkeypatch, project):
    (project / "main.vb").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("dotnet"))
    hostile = ["--version", "; echo no-shell", "$(touch hostile)", "--argument=--x", "a b"]
    result = adapter.command(_request(adapter, "visual-basic", project, "main.vb", hostile))
    assert result["argv"][9:] == hostile
    assert "shell" not in result
    for bad in (["a\x00b"], ["x"] * (adapter.MAX_ARGUMENTS + 1), ["x" * (adapter.MAX_ARGUMENT_BYTES + 1)]):
        with pytest.raises(ValueError, match="RUNNER_ARGUMENT_VECTOR_INVALID"):
            adapter.command(_request(adapter, "visual-basic", project, "main.vb", bad))


@pytest.mark.parametrize("language", ["scratch", "matlab", "sas"])
def test_arguments_are_refused_where_no_argument_contract_exists(adapter, monkeypatch, project, language):
    _materialize(project / ENTRY[language], language)
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError, match="RUNNER_ARGUMENT_VECTOR_INVALID"):
        adapter.command(_request(adapter, language, project, ENTRY[language], ["--version"]))


@pytest.mark.parametrize("mutation,message", [
    ({"language": "fortran"}, "RUNNER_EXTENSION_PROTOCOL_DIFFERS"),
    ({"schema_version": "other"}, "RUNNER_EXTENSION_PROTOCOL_DIFFERS"),
    ({"environment": "container"}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
    ({"environment": None}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
    ({"environment": {"PATH": "/opt/evil"}}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
])
def test_closed_request_surface(adapter, monkeypatch, project, mutation, message):
    (project / "main.vb").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("dotnet"))
    request = {**_request(adapter, "visual-basic", project, "main.vb"), **mutation}
    with pytest.raises(ValueError, match=message):
        adapter.command(request)


# --- scratch: closed .sb3 ZIP shape -----------------------------------------

def _archive_cases():
    def plain(path):
        path.write_text("this is not a zip", encoding="utf-8")
        return path

    def duplicate(path):
        with pytest.warns(UserWarning):
            return _write_sb3(path, members=[("project.json", "{}"), ("project.json", "{}")])

    def symlink(path):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("project.json", json.dumps(VALID_PROJECT))
            info = zipfile.ZipInfo(ASSET)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, b"project.json")
        return path

    def too_many(path):
        members = [(f"{index:032x}.svg", b"") for index in range(512)]
        return _write_sb3(path, members=members)

    def too_large(path):
        return _write_sb3(path, members=[(ASSET, b"\0" * (64 * 1024 * 1024 + 1))])

    return [
        ("valid", lambda p: _write_sb3(p), None),
        ("not-zip", plain, "not-zip"),
        ("missing-project-json", _zip_without_project, "missing-project-json"),
        ("dotdot-member", lambda p: _write_sb3(p, members=[("../escape.svg", b"x")]), "member-name"),
        ("absolute-member", lambda p: _write_sb3(p, members=[("/abs.svg", b"x")]), "member-name"),
        ("drive-member", lambda p: _write_sb3(p, members=[("C:x.svg", b"x")]), "member-name"),
        ("backslash-member", lambda p: _write_sb3(p, members=[("a\\b.svg", b"x")]), "member-name"),
        ("duplicate-member", duplicate, "duplicate-member"),
        ("symlink-member", symlink, "member-symlink"),
        ("too-many-members", too_many, "member-count"),
        ("uncompressed-too-large", too_large, "uncompressed-size"),
        ("project-json-invalid", lambda p: _raw_project(p, b"{not json"), "project-json-invalid"),
        ("no-stage", lambda p: _write_sb3(p, project_json={"targets": [
            {"name": "Sprite1", "isStage": False, "blocks": {}}]}), "project-shape"),
        ("two-stages", lambda p: _write_sb3(p, project_json={"targets": [
            {"name": "Stage", "isStage": True, "blocks": {}}, {"name": "S2", "isStage": True, "blocks": {}}]}),
         "project-shape"),
        ("target-without-blocks", lambda p: _write_sb3(p, project_json={"targets": [
            {"name": "Stage", "isStage": True}]}), "project-shape"),
    ]


def _zip_without_project(path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(ASSET, b"<svg/>")
    return path


def _raw_project(path, data):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("project.json", data)
    return path


@pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
@pytest.mark.parametrize("label,build,expected", _archive_cases(), ids=[c[0] for c in _archive_cases()])
def test_scratch_archive_shape_is_closed(adapter, tmp_path, label, build, expected):
    path = build(tmp_path / f"{label}.sb3")
    assert adapter.sb3_problem(path) == expected


def test_scratch_invalid_archive_is_refused_before_tool_lookup(adapter, monkeypatch, project):
    (project / "main.sb3").write_bytes(b"not a zip")
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("tool lookup before validation"))
    with pytest.raises(ValueError, match="RUNNER_CONTRACT_REJECTED"):
        adapter.command(_request(adapter, "scratch", project, "main.sb3"))


# --- matlab: safe identifier names only -------------------------------------

@pytest.mark.parametrize("name", ["main.m", "main_1.m", "a.m", "sub/fn.m"])
def test_matlab_accepts_identifier_stems(adapter, monkeypatch, project, name):
    target = project / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("disp('ok')\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("matlab"))
    result = adapter.command(_request(adapter, "matlab", project, name))
    assert result["argv"][8] == str(target.resolve())


@pytest.mark.parametrize("name", ["a;b.m", "x y.m", "f('x').m", "evil(1).m", "1start.m", "a-b.m", "a'b.m", "$x.m"])
def test_matlab_rejects_injection_prone_names(adapter, monkeypatch, project, name):
    (project / name).write_text("disp('ok')\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", _fake_which("matlab"))
    with pytest.raises(ValueError, match="RUNNER_CONTRACT_REJECTED"):
        adapter.command(_request(adapter, "matlab", project, name))


# --- worker: visual basic (.NET) --------------------------------------------

def test_visual_basic_build_plan_and_exact_language_selection(adapter, monkeypatch, project):
    entry = project / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")
    seen = {}

    def snapshot(argv, kwargs):
        base = Path(kwargs["cwd"])
        seen["cwd"] = str(base)
        seen["files"] = sorted(os.listdir(base))
        seen["project"] = (base / "subject.vbproj").read_text(encoding="utf-8")
        seen["source"] = (base / "subject.vb").read_bytes()

    calls, procs, code, run_calls = _worker(adapter, monkeypatch, "visual-basic", "dotnet",
                                            str(entry.resolve()), ["--flag", "v"], codes=[0, 5],
                                            effects={0: snapshot})
    base = Path(seen["cwd"])
    exe = "subject.exe" if os.name == "nt" else "subject"
    assert code == 5
    assert run_calls[0][0] == ["dotnet", "--version"]
    build_argv, build_kwargs = calls[0]
    assert build_argv == ["dotnet", "build", str(base / "subject.vbproj"), "--nologo", "-o", str(base / "out")]
    assert build_kwargs["shell"] is False and build_kwargs["stdin"] == subprocess.DEVNULL
    assert {"nosource", "subject.vb", "subject.vbproj"} <= set(seen["files"])
    assert not any(name.endswith((".cs", ".csproj")) for name in seen["files"])
    assert "<TargetFramework>net10.0</TargetFramework>" in seen["project"]
    assert "Microsoft.NET.Sdk" in seen["project"]
    assert "<NuGetAudit>false</NuGetAudit>" in seen["project"]
    assert "<Deterministic>true</Deterministic>" in seen["project"]
    assert seen["source"] == entry.read_bytes()
    assert calls[1][0] == [str(base / "out" / exe), "--flag", "v"]
    assert not base.exists()


def test_visual_basic_garbled_sdk_version_is_a_version_unknown_token(adapter, monkeypatch, project, capsys):
    entry = project / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")
    calls, procs, code, run_calls = _worker(adapter, monkeypatch, "visual-basic", "dotnet",
                                            str(entry.resolve()), [], sdk=b"not-a-version\n")
    assert code == 127
    assert "RUNNER_TOOLCHAIN_VERSION_UNKNOWN:dotnet" in capsys.readouterr().err
    assert calls == []


def test_visual_basic_build_failure_stops_before_run(adapter, monkeypatch, project):
    entry = project / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")
    calls, procs, code, run_calls = _worker(adapter, monkeypatch, "visual-basic", "dotnet",
                                            str(entry.resolve()), [], codes=[2])
    assert code == 2
    assert len(calls) == 1


def test_visual_basic_signal_exit_maps_to_shell_convention(adapter, monkeypatch, project):
    entry = project / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")
    calls, procs, code, run_calls = _worker(adapter, monkeypatch, "visual-basic", "dotnet",
                                            str(entry.resolve()), [], codes=[0, -11])
    assert code == 139
    assert len(calls) == 2


# --- worker: matlab ---------------------------------------------------------

def test_matlab_worker_runs_only_a_copy_in_a_private_directory(adapter, monkeypatch, project):
    entry = project / "main.m"
    entry.write_bytes(b"disp('ok')\n")
    seen = {}

    def snapshot(argv, kwargs):
        seen["cwd"] = kwargs["cwd"]
        seen["copy"] = (Path(kwargs["cwd"]) / "main.m").read_bytes()
        seen["names"] = set(os.listdir(kwargs["cwd"]))

    calls, procs, code, _ = _worker(adapter, monkeypatch, "matlab", "matlab", str(entry.resolve()), [],
                                    effects={0: snapshot})
    assert code == 0
    argv, kwargs = calls[0]
    assert argv == ["matlab", "-nostartup", "-batch", "main"]
    assert kwargs["cwd"] == seen["cwd"] and Path(seen["cwd"]) != project
    assert seen["copy"] == b"disp('ok')\n"
    assert "main.m" in seen["names"] and seen["names"] <= {"main.m", "matlab.log"}
    assert not Path(seen["cwd"]).exists()


def test_matlab_run_output_over_cap_is_refused(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 16")
    assert source != adapter.WORKER
    entry = project / "main.m"
    entry.write_bytes(b"disp('ok')\n")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "matlab", "matlab", str(entry.resolve()), [],
                                    effects={0: lambda argv, kwargs: kwargs["stdout"].write(b"x" * 64)},
                                    source=source)
    assert code == 125
    assert len(calls) == 1


# --- worker: sas ------------------------------------------------------------

def test_sas_worker_uses_explicit_bounded_artifacts_and_cleans_up(adapter, monkeypatch, project):
    entry = project / "main.sas"
    entry.write_text("data _null_; run;\n", encoding="utf-8")
    seen = {}

    def produce(argv, kwargs):
        seen["cwd"] = kwargs["cwd"]
        seen["copy"] = Path(argv[argv.index("-sysin") + 1])
        seen["copy_bytes"] = seen["copy"].read_bytes()
        Path(argv[argv.index("-log") + 1]).write_text("NOTE: ok\n", encoding="utf-8")
        Path(argv[argv.index("-print") + 1]).write_text("listing\n", encoding="utf-8")

    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [],
                                    effects={0: produce})
    base = Path(seen["cwd"])
    assert code == 0
    argv, kwargs = calls[0]
    assert argv == ["sas", "-nosplash", "-noterminal", "-noautoexec", "-sysin", str(base / "subject.sas"),
                    "-log", str(base / "sas.log"), "-print", str(base / "sas.lst")]
    assert kwargs["cwd"] == str(base) and kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL
    assert seen["copy"] == base / "subject.sas"
    assert seen["copy_bytes"] == entry.read_bytes()
    assert not base.exists()
    assert not (project / "sas.log").exists()


def test_sas_error_log_with_zero_exit_is_not_a_pass(adapter, monkeypatch, project):
    entry = project / "main.sas"
    entry.write_text("x\n", encoding="utf-8")

    def error_log(argv, kwargs):
        Path(argv[argv.index("-log") + 1]).write_text("ERROR: File WORK.X does not exist.\n", encoding="utf-8")

    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [],
                                    effects={0: error_log})
    assert code == 1


def test_sas_nonzero_exit_is_preserved(adapter, monkeypatch, project):
    entry = project / "main.sas"
    entry.write_text("x\n", encoding="utf-8")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [], codes=[2])
    assert code == 2
    assert len(calls) == 1


def test_sas_listing_over_cap_is_refused(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 16")
    assert source != adapter.WORKER
    entry = project / "main.sas"
    entry.write_text("x\n", encoding="utf-8")

    def big_listing(argv, kwargs):
        Path(argv[argv.index("-print") + 1]).write_text("y" * 64, encoding="utf-8")

    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [],
                                    effects={0: big_listing}, source=source)
    assert code == 125


def test_worker_timeout_kills_owned_child(adapter, monkeypatch, project):
    source = adapter.WORKER.replace("PROCESS_SECONDS = 300", "PROCESS_SECONDS = 0.2")
    assert source != adapter.WORKER
    entry = project / "main.sas"
    entry.write_text("x\n", encoding="utf-8")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [],
                                    hang={0}, source=source)
    assert code == 124
    assert len(calls) == 1
    assert procs[0].killed


def _run_helper(adapter, monkeypatch, source):
    """The worker's ``run`` helper, defined without selecting a tool: the module exits at its dialect check."""
    monkeypatch.setattr(sys, "argv", ["-c", "unknown", "tool", "entry"])
    namespace: dict[str, Any] = {"__name__": "__main__"}
    with pytest.raises(SystemExit):
        exec(compile(source, "<vstd-batch-three-worker>", "exec"), namespace)
    return namespace["run"]


def test_run_stops_a_real_child_as_soon_as_its_output_passes_the_cap(adapter, monkeypatch, project):
    source = (adapter.WORKER.replace("PROCESS_SECONDS = 300", "PROCESS_SECONDS = 15")
              .replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 1024"))
    assert source.count("PROCESS_SECONDS = 15") == 1 and source.count("OUTPUT_BYTES = 1024") == 1
    run = _run_helper(adapter, monkeypatch, source)
    child = "import sys, time; sys.stdout.write('x' * 4096); sys.stdout.flush(); time.sleep(60)"
    stream = io.BytesIO()
    started = time.monotonic()
    code = run([sys.executable, "-c", child], str(project), str(project / "run.log"), stream)
    assert code == 125
    assert time.monotonic() - started < 10
    assert stream.getvalue() == b""


def test_run_keeps_a_real_nonzero_exit_and_its_bounded_output(adapter, monkeypatch, project):
    run = _run_helper(adapter, monkeypatch, adapter.WORKER)
    child = "import sys; sys.stdout.write('ok'); sys.exit(3)"
    stream = io.BytesIO()
    assert run([sys.executable, "-c", child], str(project), str(project / "run.log"), stream) == 3
    assert stream.getvalue() == b"ok"


# --- worker: scratch --------------------------------------------------------

def test_scratch_static_check_never_substitutes_for_the_runner(adapter, monkeypatch, project):
    valid = _write_sb3(project / "main.sb3")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "scratch", "scratch-vm-headless",
                                    str(valid.resolve()), [], codes=[0])
    assert code == 0
    argv, kwargs = calls[0]
    assert len(calls) == 1
    assert argv == ["scratch-vm-headless", str(Path(kwargs["cwd"]) / "project.sb3")]
    assert not Path(kwargs["cwd"]).exists()

    bad = project / "bad.sb3"
    bad.write_bytes(b"not a zip")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "scratch", "scratch-vm-headless",
                                    str(bad.resolve()), [], codes=[0])
    assert code == 1
    assert calls == []


def test_scratch_runner_exit_is_preserved(adapter, monkeypatch, project):
    valid = _write_sb3(project / "main.sb3")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "scratch", "scratch-vm-headless",
                                    str(valid.resolve()), [], codes=[3])
    assert code == 3
    assert len(calls) == 1


# --- real specimens: classified skips when the tool is absent ---------------

@pytest.mark.parametrize("language", ["visual-basic", "matlab", "sas"])
def test_real_specimen_end_to_end(adapter, project, language):
    name = ENTRY[language]
    tool = TOOLS[language]
    if shutil.which(tool) is None:
        pytest.skip(f"RUNNER_TOOLCHAIN_MISSING:{tool} (classified skip; not a PASS)")
    (project / name).write_text(BODIES[language], encoding="utf-8")
    before = sorted(os.listdir(project))
    result = adapter.command(_request(adapter, language, project, name))
    completed = subprocess.run(result["argv"], capture_output=True, timeout=600, shell=False, cwd=str(project))
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    if language != "sas":
        assert b"ok" in completed.stdout
    assert sorted(os.listdir(project)) == before


def test_scratch_real_runner_is_a_classified_skip_when_absent(adapter, project):
    if shutil.which("scratch-vm-headless") is None:
        pytest.skip("RUNNER_TOOLCHAIN_MISSING:scratch-vm-headless (classified skip; not a PASS)")
    _write_sb3(project / "main.sb3")
    result = adapter.command(_request(adapter, "scratch", project, "main.sb3"))
    completed = subprocess.run(result["argv"], capture_output=True, timeout=600, shell=False, cwd=str(project))
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")


def test_classic_visual_basic_real_specimen_is_never_run(adapter, project):
    (project / "main.bas").write_text('Attribute VB_Name = "Main"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="^RUNNER_LANGUAGE_UNSUPPORTED$"):
        adapter.command(_request(adapter, "classic-visual-basic", project, "main.bas"))


# --- hardening: an in-root symlink cannot change the declared dialect ---------

@pytest.mark.parametrize("language", IMPLEMENTED)
def test_in_root_symlink_cannot_change_the_declared_dialect(adapter, monkeypatch, project, language):
    suffix = sorted(SUFFIXES[language])[0]
    (project / "real.txt").write_text("x\n", encoding="utf-8")
    try:
        (project / f"link{suffix}").symlink_to(project / "real.txt")
    except OSError:
        pytest.skip("symlink creation needs privileges on this host; dialect-by-target check not exercised")
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    with pytest.raises(ValueError, match="^RUNNER_DIALECT_UNSUPPORTED$"):
        adapter.command(_request(adapter, language, project, f"link{suffix}"))


# --- characterization: an understated central-directory size cannot widen the read ---

def test_scratch_understated_header_never_widens_the_project_json_read(adapter, tmp_path):
    """CPython's ZipExtFile stops at the declared size, so a too-small header yields an invalid
    read rather than an unbounded inflate; the declared-size cap above still covers honest headers."""
    path = tmp_path / "understated.sb3"
    body = json.dumps(VALID_PROJECT).encode("utf-8") + b" " * (16 * 1024 * 1024 + 1)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("project.json", body)
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    raw[central + 24:central + 28] = (64).to_bytes(4, "little")
    path.write_bytes(bytes(raw))
    assert adapter.sb3_problem(path) == "project-json-invalid"


# --- residual 1: dotnet --version probe failures are typed tokens, never tracebacks ---

def _probe_worker(adapter, monkeypatch, tmp_path, probe):
    """Run the Visual Basic worker with ``probe`` answering ``dotnet --version``; no build may start."""
    entry = tmp_path / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")

    def fake_run(argv, **kwargs):
        if list(argv[1:]) == ["--version"]:
            return probe(argv, kwargs)
        pytest.fail("no build may start after a failed software development kit (SDK) probe")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: pytest.fail("no process after a failed probe"))
    monkeypatch.setattr(sys, "argv", ["-c", "visual-basic", "dotnet", str(entry.resolve())])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-batch-three-worker>", "exec"), {"__name__": "__main__"})
    return stopped.value.code


@pytest.mark.parametrize("failure,token,code", [
    (subprocess.TimeoutExpired(["dotnet", "--version"], 60), "RUNNER_TOOLCHAIN_VERSION_UNKNOWN:dotnet", 127),
    (FileNotFoundError(2, "No such file", "dotnet"), "RUNNER_TOOLCHAIN_MISSING:dotnet", 127),
    (PermissionError(13, "Permission denied", "dotnet"), "RUNNER_TOOLCHAIN_MISSING:dotnet", 127),
], ids=["timeout", "missing", "denied"])
def test_dotnet_probe_exceptions_return_a_typed_token_without_traceback(adapter, monkeypatch, tmp_path, capsys,
                                                                       failure, token, code):
    def raise_failure(argv, kwargs):
        raise failure

    assert _probe_worker(adapter, monkeypatch, tmp_path, raise_failure) == code
    err = capsys.readouterr().err
    assert token in err
    assert "Traceback" not in err


def test_dotnet_probe_nonzero_exit_is_version_unknown(adapter, monkeypatch, tmp_path, capsys):
    def nonzero(argv, kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"broken")

    assert _probe_worker(adapter, monkeypatch, tmp_path, nonzero) == 127
    assert "RUNNER_TOOLCHAIN_VERSION_UNKNOWN:dotnet" in capsys.readouterr().err


# --- residual 2: worker timeout, output and spawn outcomes use the normalized tokens ---

def test_sas_timeout_is_the_stable_extension_token_with_unknown_cleanup(adapter, monkeypatch, project, capsys):
    source = adapter.WORKER.replace("PROCESS_SECONDS = 300", "PROCESS_SECONDS = 0.2")
    assert source != adapter.WORKER
    entry = project / "main.sas"
    entry.write_text("x\n", encoding="utf-8")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "sas", "sas", str(entry.resolve()), [],
                                    hang={0}, source=source)
    assert code == 124
    assert "VSTD_EXTENSION_TIMEOUT:sas cleanup=UNKNOWN" in capsys.readouterr().err


def test_matlab_output_cap_is_the_stable_extension_token(adapter, monkeypatch, project, capsys):
    source = adapter.WORKER.replace("OUTPUT_BYTES = 65536", "OUTPUT_BYTES = 16")
    entry = project / "main.m"
    entry.write_bytes(b"disp('ok')\n")
    calls, procs, code, _ = _worker(adapter, monkeypatch, "matlab", "matlab", str(entry.resolve()), [],
                                    effects={0: lambda argv, kwargs: kwargs["stdout"].write(b"x" * 64)},
                                    source=source)
    assert code == 125
    assert "VSTD_EXTENSION_OUTPUT_LIMIT:matlab cleanup=UNKNOWN" in capsys.readouterr().err


def test_scratch_runner_missing_at_spawn_is_the_toolchain_token(adapter, monkeypatch, project, capsys):
    valid = _write_sb3(project / "main.sb3")

    def missing(argv, **kwargs):
        raise FileNotFoundError(2, "No such file", argv[0])

    monkeypatch.setattr(subprocess, "Popen", missing)
    monkeypatch.setattr(sys, "argv", ["-c", "scratch", "scratch-vm-headless", str(valid.resolve())])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-batch-three-worker>", "exec"), {"__name__": "__main__"})
    assert stopped.value.code == 127
    assert "RUNNER_TOOLCHAIN_MISSING:scratch-vm-headless" in capsys.readouterr().err


def test_visual_basic_artifact_that_cannot_start_is_the_resource_token(adapter, monkeypatch, project, capsys):
    entry = project / "main.vb"
    entry.write_text(BODIES["visual-basic"], encoding="utf-8")
    spawned = []

    def popen(argv, **kwargs):
        spawned.append(argv)
        if len(spawned) == 2:
            raise PermissionError(13, "Permission denied", argv[0])
        return _FakeProcess(0)

    def probe(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"10.0.100\n", stderr=b"")

    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "run", probe)
    monkeypatch.setattr(sys, "argv", ["-c", "visual-basic", "dotnet", str(entry.resolve())])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(adapter.WORKER, "<vstd-batch-three-worker>", "exec"), {"__name__": "__main__"})
    assert stopped.value.code == 126
    assert "RUNNER_RESOURCE_UNAVAILABLE:run" in capsys.readouterr().err


# --- residual 3: one environment declaration rule across batch two and three ---

@pytest.mark.parametrize("language,entry", [("visual-basic", "main.vb"), ("matlab", "main.m"), ("sas", "main.sas")])
def test_explicit_host_environment_is_accepted_like_batch_two(adapter, monkeypatch, project, language, entry):
    _materialize(project / entry, language)
    monkeypatch.setattr(shutil, "which", _fake_which(TOOLS[language]))
    request = {**_request(adapter, language, project, entry), "environment": "host"}
    assert adapter.command(request)["language"] == language


@pytest.mark.parametrize("environment", [None, "container", {"PATH": "/opt/evil"}])
def test_environment_refusal_happens_before_any_lookup(adapter, monkeypatch, project, environment):
    _materialize(project / "main.sas", "sas")
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("lookup before environment check"))
    with pytest.raises(ValueError, match="^RUNNER_ENVIRONMENT_UNSUPPORTED$"):
        adapter.command({**_request(adapter, "sas", project, "main.sas"), "environment": environment})


@pytest.mark.parametrize("language", IMPLEMENTED)
def test_sandbox_linux_constructs_bounded_remote_worker_without_host_lookup(
    adapter, monkeypatch, language
):
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("host lookup"))
    arguments = ["; echo no-shell", "a b"] if language == "visual-basic" else []
    request = {
        "schema_version": adapter.PROTOCOL,
        "language": language,
        "root": "/sandbox/source",
        "entry": "nested/" + ENTRY[language],
        "arguments": arguments,
        "environment": "sandbox-linux",
    }
    response = adapter.command(request)
    assert response["argv"][:4] == ["python3", "-I", "-B", "-c"]
    assert response["argv"][4:6] == [adapter.WORKER_LAUNCHER, adapter.WORKER_PAYLOAD]
    assert max(map(len, response["argv"])) <= 8192
    assert response["argv"][6:9] == [
        language,
        TOOLS[language],
        "/sandbox/source/nested/" + ENTRY[language],
    ]
    assert response["argv"][9:] == arguments


@pytest.mark.parametrize("entry", ["../escape.sas", "/absolute.sas", "nested\\escape.sas", "-option.sas"])
def test_sandbox_linux_rejects_entry_escape_before_host_lookup(adapter, monkeypatch, entry):
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("host lookup"))
    with pytest.raises(ValueError):
        adapter.command({
            "schema_version": adapter.PROTOCOL,
            "language": "sas",
            "root": "/sandbox/source",
            "entry": entry,
            "arguments": [],
            "environment": "sandbox-linux",
        })


# --- residual 4: deadline tree kill on Windows, observed on a live grandchild ---

@pytest.mark.skipif(os.name != "nt", reason="the deadline tree kill evidence is the Windows taskkill path")
def test_run_deadline_tree_kill_stops_a_live_grandchild_on_windows(adapter, monkeypatch, tmp_path):
    beat, pid_file = tmp_path / "beat.txt", tmp_path / "pid.txt"
    grandchild = (f"import os, pathlib, time\n"
                  f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                  f"p = pathlib.Path({str(beat)!r})\n"
                  "while True:\n    with p.open('a') as h: h.write('x')\n    time.sleep(0.05)\n")
    driver = ("import subprocess, sys, time\n"
              f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\ntime.sleep(120)\n")
    source = adapter.WORKER.replace("PROCESS_SECONDS = 300", "PROCESS_SECONDS = 2")
    assert source != adapter.WORKER
    run = _run_helper(adapter, monkeypatch, source)
    stream = io.BytesIO()
    try:
        assert run([sys.executable, "-c", driver], str(tmp_path), str(tmp_path / "run.log"), stream) == 124
        assert beat.exists() and beat.stat().st_size > 0, "the grandchild never started; the check would prove nothing"
        size_at_return = beat.stat().st_size
        time.sleep(1.0)
        assert beat.stat().st_size == size_at_return, "a grandchild kept running after the deadline"
    finally:
        if pid_file.exists():
            subprocess.run(["taskkill", "/T", "/F", "/PID", pid_file.read_text(encoding="utf-8")],
                           capture_output=True, shell=False)
