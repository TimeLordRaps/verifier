"""Adversarial regressions for trusted-local runner dispatch.

Covers subject drift after execution (self-rewrite, rename, metadata-only change), tool
lookup that must not select an executable from the subject root, directory links during
detection, and adapter control flow that ends the host (SystemExit). Expected outcomes are
closed UNKNOWN or FAIL reports with a closed blocker code; no test accepts a silent pass.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from verifier.core import run as run_module
from verifier.core.run_process_observation import (
    begin_parent_process_observation,
    observe_completed_process,
)
from verifier.runtime import language_runners as runners
from verifier.runtime.public_cli import main

# Windows CreateProcess and PATH search skip the current directory when this variable is "1".
# The ambient value on some hosts hides the cwd-lookup defect, so tests clear it explicitly.
NO_CWD_EXE = "NoDefaultCurrentDirectoryInExePath"


@pytest.fixture
def cwd_lookup_enabled(monkeypatch):
    monkeypatch.delenv(NO_CWD_EXE, raising=False)
    return monkeypatch


def _report(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def _completed_capture(mutate, returncode: int = 0, calls: list | None = None):
    """Replace capture_run: run ``mutate`` as the subject, then report a completed process."""

    def fake(manifest, manifest_dir):
        if calls is not None:
            calls.append(manifest)
        launch = begin_parent_process_observation(
            argv=manifest["command"],
            declared_cwd=manifest["cwd"],
            resolved_cwd=Path(manifest_dir),
            timeout_seconds=manifest["timeout_seconds"],
        )
        mutate()
        observation = observe_completed_process(launch, returncode=returncode, stdout=b"", stderr=b"",
                                                owned_tree_cleanup="CONFIRMED")
        data = {"execution": {"exit_code": returncode},
                "assessment_context": {"refutation_surface": {"parent_process_observation": observation}}}
        return SimpleNamespace(execution=SimpleNamespace(exit_code=returncode), to_dict=lambda: data)

    return fake


def _write_python_entry(root: Path, text: str = "print('admitted')") -> Path:
    entry = root / "main.py"
    entry.write_text(text, encoding="utf-8")
    return entry


def _run_python(root: Path, capsys) -> tuple[int, dict]:
    code = main(["runner", "run", "main.py", "--root", str(root), "--trusted-local", "--json"])
    return code, _report(capsys)


def _adapter_argv(monkeypatch, argv: list[str]) -> None:
    """Make the javascript adapter return ``argv`` as its bounded command vector."""

    class Extension:
        name = "javascript"

        def load(self):
            def command(_request):
                return {"schema_version": runners.PROTOCOL, "language": "javascript", "argv": list(argv)}

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])


def _run_adapter(root: Path, capsys) -> tuple[int, dict]:
    (root / "main.js").write_text("console.log(1)", encoding="utf-8")
    code = main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(root), "--json"])
    return code, _report(capsys)


def _shell_argv(text: str) -> list[str]:
    """Argument vector for a tool that echoes ``text``: cmd.exe on Windows, sh elsewhere."""
    return ["/c", f"echo {text}"] if sys.platform == "win32" else ["-c", f"echo {text}"]


def _tool_copy(directory: Path, name: str) -> Path:
    """A real executable copy named ``name`` inside ``directory``; each copy echoes its argv."""
    directory.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        target = directory / f"{name}.exe"
        shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", target)
    else:
        target = directory / name
        shutil.copy(shutil.which("sh"), target)
    return target


# --- F2: subject immutability -------------------------------------------------------------

def test_unchanged_subject_keeps_pass_and_observes_entry_on_both_sides(tmp_path, capsys, monkeypatch) -> None:
    _write_python_entry(tmp_path)
    monkeypatch.setattr(run_module, "capture_run", _completed_capture(lambda: None))
    code, report = _run_python(tmp_path, capsys)
    assert code == 0
    assert report["status"] == "PASS"
    assert report["blockers"] == []
    assert report["polished"] is False
    integrity = report["subject_integrity"]
    assert integrity["status"] == "UNCHANGED"
    assert integrity["scope"] == "selected_entry_only"
    assert integrity["before"] == integrity["after"]
    assert integrity["before"]["state"] == "OBSERVED"


@pytest.mark.parametrize("drift", ["rewrite", "rename_identical", "delete_recreate_identical", "metadata_only"])
def test_subject_drift_after_exit_zero_is_unknown_not_pass(tmp_path, capsys, monkeypatch, drift) -> None:
    entry = _write_python_entry(tmp_path)

    def mutate() -> None:
        if drift == "rewrite":
            entry.write_text("print('rewritten')", encoding="utf-8")
        elif drift == "rename_identical":
            # Same bytes, new file identity: the content hash cannot see this, the identity must.
            staged = tmp_path / "staged.py"
            staged.write_bytes(entry.read_bytes())
            os.replace(staged, entry)
        elif drift == "delete_recreate_identical":
            # Same bytes and restored mtime; only the new file's own creation/change time and identity differ.
            data, before = entry.read_bytes(), entry.stat()
            entry.unlink()
            entry.write_bytes(data)
            os.utime(entry, ns=(before.st_atime_ns, before.st_mtime_ns))
        else:
            stat = entry.stat()
            os.utime(entry, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))

    monkeypatch.setattr(run_module, "capture_run", _completed_capture(mutate, returncode=0))
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["polished"] is False
    integrity = report["subject_integrity"]
    assert integrity["status"] == "CHANGED"
    assert integrity["before"]["state"] == integrity["after"]["state"] == "OBSERVED"
    assert integrity["before"] != integrity["after"]
    # The original receipt is preserved, not overwritten by the drift observation.
    assert report["receipt"]["execution"]["exit_code"] == 0
    assert report["execution_performed"] is True
    assert isinstance(report["reason"], str) and isinstance(report["next_action"], str)


def test_real_process_self_rewrite_then_exit_zero_is_not_pass(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text(
        "import pathlib\n"
        "pathlib.Path(__file__).write_text(\"print('rewritten')\", encoding='utf-8')\n",
        encoding="utf-8",
    )
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["receipt"]["execution"]["exit_code"] == 0
    before = report["subject_integrity"]["before"]
    after = report["subject_integrity"]["after"]
    assert before["sha256"] != after["sha256"]
    # The receipt's pre-run input digest is the before observation, unchanged by the drift check.
    assert report["receipt"]["inputs"][0]["sha256"] == before["sha256"]


# --- F3: tool lookup ----------------------------------------------------------------------

def test_bare_tool_name_never_resolves_to_subject_root_copy(tmp_path, capsys, cwd_lookup_enabled) -> None:
    _tool_copy(tmp_path, "fakeverifiertool")
    cwd_lookup_enabled.chdir(tmp_path)
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("ROOT")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_TOOLCHAIN_MISSING:fakeverifiertool"]
    assert report["execution_attempted"] is False
    assert report["receipt"] is None


def test_trusted_path_tool_is_executed_by_absolute_path_not_root_copy(
    tmp_path, tmp_path_factory, capsys, cwd_lookup_enabled,
) -> None:
    trusted = _tool_copy(tmp_path_factory.mktemp("trusted-bin"), "fakeverifiertool")
    _tool_copy(tmp_path, "fakeverifiertool")
    cwd_lookup_enabled.setenv("PATH", str(trusted.parent) + os.pathsep + os.environ["PATH"])
    cwd_lookup_enabled.chdir(tmp_path)
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("TRUSTED")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 0
    executed = Path(report["receipt"]["execution"]["command"][0])
    assert executed.is_absolute()
    assert executed.resolve() == trusted.resolve()
    assert "TRUSTED" in report["receipt"]["execution"]["stdout_snippet"]


def test_path_entry_inside_subject_root_is_refused(tmp_path, capsys, cwd_lookup_enabled) -> None:
    _tool_copy(tmp_path / "bin", "fakeverifiertool")
    cwd_lookup_enabled.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    cwd_lookup_enabled.chdir(tmp_path)
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("ROOT")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False
    assert report["receipt"] is None


@pytest.mark.parametrize("form", ["absolute-inside-root", "relative-with-separator"])
def test_subject_root_tool_named_by_path_is_refused(tmp_path, capsys, cwd_lookup_enabled, form) -> None:
    tool = _tool_copy(tmp_path, "fakeverifiertool")
    name = str(tool) if form == "absolute-inside-root" else "./fakeverifiertool"
    _adapter_argv(cwd_lookup_enabled, [name, *_shell_argv("ROOT")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False


def test_absolute_tool_outside_root_runs_as_given(tmp_path, tmp_path_factory, capsys, cwd_lookup_enabled) -> None:
    trusted = _tool_copy(tmp_path_factory.mktemp("absolute-bin"), "fakeverifiertool")
    _adapter_argv(cwd_lookup_enabled, [str(trusted), *_shell_argv("ABSOLUTE")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 0
    assert Path(report["receipt"]["execution"]["command"][0]).resolve() == trusted.resolve()
    assert "ABSOLUTE" in report["receipt"]["execution"]["stdout_snippet"]


def test_current_directory_opt_out_is_scoped_to_the_child_call(tmp_path, capsys, monkeypatch, cwd_lookup_enabled) -> None:
    _write_python_entry(tmp_path)
    seen: dict[str, str | None] = {}

    def mutate() -> None:
        seen["during"] = os.environ.get(NO_CWD_EXE)

    monkeypatch.setattr(run_module, "capture_run", _completed_capture(mutate))
    code, _ = _run_python(tmp_path, capsys)
    assert code == 0
    assert seen["during"] == ("1" if sys.platform == "win32" else None)
    assert os.environ.get(NO_CWD_EXE) is None


@pytest.mark.skipif(sys.platform != "win32",
                    reason="OS_CAPABILITY_GUARD: NoDefaultCurrentDirectoryInExePath is a Windows search control")
def test_real_child_inherits_current_directory_opt_out_on_windows(tmp_path, capsys, cwd_lookup_enabled) -> None:
    _adapter_argv(cwd_lookup_enabled, [sys.executable, "-B", "-c",
                                       f"import os; print(os.environ.get('{NO_CWD_EXE}'))"])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 0
    assert "1" in report["receipt"]["execution"]["stdout_snippet"].split()


# --- F9: directory links during detection -------------------------------------------------

def _make_directory_link(link: Path, target: Path) -> str:
    """Create a Windows junction or a POSIX symlink; skip under the capability guard if unavailable."""
    if sys.platform == "win32":
        completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                                   capture_output=True, text=True)
        if completed.returncode != 0 or not link.exists():
            pytest.skip("OS_CAPABILITY_GUARD: directory junction creation unavailable on this host")
        return "reparse"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("OS_CAPABILITY_GUARD: symbolic link creation unavailable on this host")
    return "symlink"


def test_directory_links_are_not_traversed_into_outside_names(tmp_path, tmp_path_factory) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (outside / "outside_secret_module.py").write_text("", encoding="utf-8")
    (outside / "outside_secret_script.js").write_text("", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "inside.py").write_text("", encoding="utf-8")
    kind = _make_directory_link(root / "linked", outside)
    result = runners.detect_languages(root)
    assert result["languages"] == {"python": 1}
    assert result["examined_file_count"] == 1
    assert result["status"] == "PASS"
    key = "reparse_points_skipped" if kind == "reparse" else "symlinks_skipped"
    assert result[key] == 1
    assert "outside_secret" not in json.dumps(result)


# --- F10: adapter control flow that ends the host -----------------------------------------

class _HostilePayload:
    def __str__(self) -> str:
        raise RuntimeError("hostile payload")

    __repr__ = __str__


def _adapter_raising(monkeypatch, error: BaseException) -> None:

    class Extension:
        name = "javascript"

        def load(self):
            def command(_request):
                raise error

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])


@pytest.mark.parametrize("payload", [
    pytest.param(0, id="int-zero"),
    pytest.param(2, id="int-two"),
    pytest.param("adapter said secret text", id="string"),
    pytest.param(_HostilePayload(), id="hostile-object"),
])
def test_adapter_system_exit_is_closed_unknown(tmp_path, capsys, monkeypatch, payload) -> None:
    _adapter_raising(monkeypatch, SystemExit(payload))
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_ADAPTER_TERMINATED"]
    assert report["execution_attempted"] is False
    assert report["execution_performed"] is False
    assert "secret" not in json.dumps(report)


def test_backend_system_exit_is_closed_and_marks_execution_indeterminate(tmp_path, capsys, monkeypatch) -> None:

    class Backend:
        name = "openshell"

        def load(self):
            def run(_request):
                raise SystemExit(3)

            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    code = main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["blockers"] == ["RUNNER_ADAPTER_TERMINATED"]
    assert report["execution_attempted"] is True
    assert report["execution_performed"] is None
    assert report["sandbox_status"] == "NOT_ESTABLISHED"
    assert report["polished"] is False


def test_keyboard_interrupt_from_adapter_propagates_to_host(tmp_path, monkeypatch) -> None:
    _adapter_raising(monkeypatch, KeyboardInterrupt())
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    with pytest.raises(KeyboardInterrupt):
        main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
              "--root", str(tmp_path), "--json"])


def test_memory_error_from_adapter_is_reported_not_swallowed(tmp_path, capsys, monkeypatch) -> None:
    _adapter_raising(monkeypatch, MemoryError())
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]


class _HostileArgs(FileNotFoundError):
    @property
    def args(self):  # type: ignore[override]
        raise SystemExit("hostile args")


class _HostileStr(FileNotFoundError):
    def __str__(self) -> str:
        raise SystemExit("hostile str")


class _HostileRepr(FileNotFoundError):
    def __repr__(self) -> str:
        raise SystemExit("hostile repr")


class _HostileFilename(FileNotFoundError):
    @property
    def filename(self):  # type: ignore[override]
        raise SystemExit("hostile filename")


class _HostileValueArgs(ValueError):
    @property
    def args(self):  # type: ignore[override]
        raise SystemExit("hostile value args")


class _HostileClassExit(SystemExit):
    @property
    def __class__(self):  # type: ignore[override]
        raise SystemExit("hostile class")


class _HostileClassInterrupt(KeyboardInterrupt):
    @property
    def __class__(self):  # type: ignore[override]
        raise SystemExit("hostile interrupt class")


def _contained(call):
    """Run ``call``; an escaped BaseException is reported by type only, so its payload is never formatted."""
    try:
        return call(), None
    except BaseException as escaped:  # the containment itself is the behavior under test
        return None, type(escaped)


@pytest.mark.parametrize("error", [
    pytest.param(_HostileArgs("RUNNER_TOOLCHAIN_MISSING:gcc"), id="args-raises-system-exit"),
    pytest.param(_HostileStr("RUNNER_TOOLCHAIN_MISSING:gcc"), id="str-raises-system-exit"),
    pytest.param(_HostileRepr("RUNNER_TOOLCHAIN_MISSING:gcc"), id="repr-raises-system-exit"),
    pytest.param(_HostileFilename("RUNNER_TOOLCHAIN_MISSING:gcc"), id="filename-raises-system-exit"),
])
def test_hostile_file_not_found_payload_is_closed_resource_blocker(tmp_path, capsys, monkeypatch, error) -> None:
    _adapter_raising(monkeypatch, error)
    outcome, escaped = _contained(lambda: _run_adapter(tmp_path, capsys))
    assert escaped is None, f"escaped as {escaped.__name__}"
    code, report = outcome
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]
    assert report["execution_attempted"] is False
    assert "hostile" not in json.dumps(report)


def test_hostile_value_error_args_are_closed_contract_blocker(tmp_path, capsys, monkeypatch) -> None:
    _adapter_raising(monkeypatch, _HostileValueArgs("RUNNER_ENTRY_MISSING"))
    outcome, escaped = _contained(lambda: _run_adapter(tmp_path, capsys))
    assert escaped is None, f"escaped as {escaped.__name__}"
    code, report = outcome
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_CONTRACT_REJECTED"]


def test_hostile_class_property_on_system_exit_is_closed_unknown(tmp_path, capsys, monkeypatch) -> None:
    _adapter_raising(monkeypatch, _HostileClassExit(0))
    outcome, escaped = _contained(lambda: _run_adapter(tmp_path, capsys))
    assert escaped is None, f"escaped as {escaped.__name__}"
    code, report = outcome
    assert code == 2
    assert report["blockers"] == ["RUNNER_ADAPTER_TERMINATED"]
    assert report["execution_attempted"] is False


def test_hostile_class_property_on_interrupt_still_propagates(tmp_path, monkeypatch) -> None:
    _adapter_raising(monkeypatch, _HostileClassInterrupt())
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    _, escaped = _contained(lambda: main(["runner", "run", "main.js", "--language", "javascript",
                                          "--trusted-local", "--root", str(tmp_path), "--json"]))
    assert escaped is not None and issubclass(escaped, KeyboardInterrupt)


def test_hostile_detection_payload_is_closed_resource_blocker(tmp_path, capsys, monkeypatch) -> None:
    def detect(_root, **_kwargs):
        raise _HostileArgs("RUNNER_TOOLCHAIN_MISSING:gcc")

    monkeypatch.setattr(runners, "detect_languages", detect)
    outcome, escaped = _contained(lambda: main(["runner", "detect", str(tmp_path), "--json"]))
    assert escaped is None, f"escaped as {escaped.__name__}"
    assert outcome == 2
    report = _report(capsys)
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]
    assert "hostile" not in json.dumps(report)


# --- F2: adapter hook mutation before the baseline ----------------------------------------

def _adapter_hooked(monkeypatch, hook, argv: list[str]) -> None:
    """Javascript adapter whose hook runs inside command(), i.e. before any trusted-local launch."""

    class Extension:
        name = "javascript"

        def load(self):
            def command(_request):
                hook()
                return {"schema_version": runners.PROTOCOL, "language": "javascript", "argv": list(argv)}

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])


def _mutate_entry(entry: Path, kind: str) -> None:
    if kind == "rewrite":
        entry.write_text("console.log('hooked rewrite')", encoding="utf-8")
    elif kind == "rename_identical":
        staged = entry.with_name("staged.js")
        staged.write_bytes(entry.read_bytes())
        os.replace(staged, entry)
    elif kind == "delete_recreate_identical":
        data, before = entry.read_bytes(), entry.stat()
        entry.unlink()
        entry.write_bytes(data)
        os.utime(entry, ns=(before.st_atime_ns, before.st_mtime_ns))
    else:
        before = entry.stat()
        os.utime(entry, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))


_HOOK_KINDS = ["rewrite", "rename_identical", "delete_recreate_identical", "metadata_only"]


@pytest.mark.parametrize("kind", _HOOK_KINDS)
def test_adapter_hook_mutation_before_baseline_is_unknown_and_not_launched(tmp_path, capsys, monkeypatch, kind) -> None:
    entry = tmp_path / "main.js"
    entry.write_text("console.log(1)", encoding="utf-8")
    calls: list = []
    monkeypatch.setattr(run_module, "capture_run", _completed_capture(lambda: None, calls=calls))
    _adapter_hooked(monkeypatch, lambda: _mutate_entry(entry, kind), [sys.executable, "-B", "-c", "pass"])
    code = main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(tmp_path), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert calls == []
    assert report["execution_attempted"] is False
    integrity = report["subject_integrity"]
    assert integrity["status"] == "CHANGED"
    assert integrity["baseline"] == "before_adapter_or_backend_hook"
    assert integrity["before"]["state"] == integrity["after"]["state"] == "OBSERVED"
    assert integrity["before"] != integrity["after"]


def test_adapter_hook_rewrite_with_real_process_is_not_pass(tmp_path, capsys, monkeypatch) -> None:
    entry = tmp_path / "main.js"
    entry.write_text("console.log(1)", encoding="utf-8")
    _adapter_hooked(monkeypatch, lambda: _mutate_entry(entry, "rewrite"), [sys.executable, "-B", "-c", "pass"])
    code = main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(tmp_path), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["receipt"] is None


def test_backend_hook_rewrite_before_result_is_unknown(tmp_path, capsys, monkeypatch) -> None:
    entry = tmp_path / "main.py"
    entry.write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")

    class Backend:
        name = "openshell"

        def load(self):
            def run(_request):
                _mutate_entry(entry, "rewrite")
                return {"schema_version": "verifier-openshell-result-1", "status": "PASS",
                        "execution_performed": True, "blockers": [], "sandbox_status": "NOT_ESTABLISHED"}

            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    code = main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["subject_integrity"]["status"] == "CHANGED"


@pytest.mark.parametrize("state", ["UNOBSERVABLE", "UNSTABLE_OBSERVATION", "NOT_REGULAR_FILE"])
def test_unobservable_baseline_is_unknown_and_never_launches(tmp_path, capsys, monkeypatch, state) -> None:
    _write_python_entry(tmp_path)
    monkeypatch.setattr(runners, "_observe_subject", lambda entry, root: {"state": state, "relative_path": "main.py"})
    calls = _stub_launch(monkeypatch)
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED"]
    assert report["execution_attempted"] is False
    assert calls == []


def test_unobservable_baseline_never_reaches_sandbox_backend(tmp_path, capsys, monkeypatch) -> None:
    _write_python_entry(tmp_path)
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(runners, "_observe_subject",
                        lambda entry, root: {"state": "UNOBSERVABLE", "relative_path": "main.py"})
    reached: list[str] = []

    class Backend:
        name = "openshell"

        def load(self):
            reached.append("load")

            def run(_request):
                reached.append("run")
                return {"schema_version": "verifier-openshell-result-1", "status": "PASS",
                        "execution_performed": True, "blockers": [], "sandbox_status": "NOT_ESTABLISHED"}

            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    code = main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED"]
    assert report["execution_attempted"] is False
    assert reached == []


def test_subject_unobservable_after_run_is_unknown_not_pass(tmp_path, capsys, monkeypatch) -> None:
    entry = _write_python_entry(tmp_path)
    monkeypatch.setattr(run_module, "capture_run", _completed_capture(lambda: entry.unlink(), returncode=0))
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["subject_integrity"]["after"]["state"] == "UNOBSERVABLE"


def test_transient_rewrite_and_restore_between_samples_is_not_pass(tmp_path, capsys, monkeypatch) -> None:
    entry = _write_python_entry(tmp_path)
    original = entry.read_bytes()

    def mutate() -> None:
        # Same-size rewrite, then the original bytes and modification time restored before the exit sample.
        stamp = entry.stat()
        entry.write_bytes(bytes(byte ^ 0x01 for byte in original))
        entry.write_bytes(original)
        os.utime(entry, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))

    monkeypatch.setattr(run_module, "capture_run", _completed_capture(mutate, returncode=0))
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    integrity = report["subject_integrity"]
    # The endpoint samples agree on bytes and modification time; the handle-derived change time (ctime_ns) is what moves.
    # A path lstat does not advance it on Windows, so the observation must stay handle-based.
    assert integrity["before"]["sha256"] == integrity["after"]["sha256"]
    assert integrity["before"]["mtime_ns"] == integrity["after"]["mtime_ns"]
    assert integrity["before"]["ctime_ns"] != integrity["after"]["ctime_ns"]


def test_real_process_transient_rewrite_and_restore_is_not_pass(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text(
        "import os, pathlib\n"
        "p = pathlib.Path(__file__)\n"
        "original = p.read_bytes()\n"
        "stamp = p.stat()\n"
        "p.write_bytes(bytes(byte ^ 0x01 for byte in original))\n"
        "p.write_bytes(original)\n"
        "os.utime(p, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))\n",
        encoding="utf-8",
    )
    code, report = _run_python(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED"]
    assert report["receipt"]["execution"]["exit_code"] == 0


# --- F3: tool identity, hard links, swap after resolution, ambient PATH ------------------

def _stub_launch(monkeypatch) -> list:
    """Record each launch the runner would make, without starting a process."""
    calls: list = []
    monkeypatch.setattr(run_module, "capture_run", _completed_capture(lambda: None, calls=calls))
    return calls


def _hardlink_or_skip(target: Path, link: Path) -> None:
    try:
        os.link(target, link)
    except OSError:
        pytest.skip("OS_CAPABILITY_GUARD: hard link creation unavailable on this host")


def test_outside_hardlink_to_subject_root_executable_is_refused(tmp_path, tmp_path_factory, capsys,
                                                                cwd_lookup_enabled) -> None:
    subject = _tool_copy(tmp_path, "fakeverifiertool")
    outside = tmp_path_factory.mktemp("alias-bin") / subject.name
    _hardlink_or_skip(subject, outside)
    calls = _stub_launch(cwd_lookup_enabled)
    _adapter_argv(cwd_lookup_enabled, [str(outside), *_shell_argv("ALIAS")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False
    assert report["receipt"] is None
    assert calls == []


def test_outside_hardlink_to_selected_entry_is_refused(tmp_path, tmp_path_factory, capsys,
                                                       cwd_lookup_enabled) -> None:
    entry = tmp_path / "main.js"
    entry.write_text("console.log(1)", encoding="utf-8")
    outside = tmp_path_factory.mktemp("entry-alias-bin") / "fakeverifiertool"
    _hardlink_or_skip(entry, outside)
    calls = _stub_launch(cwd_lookup_enabled)
    _adapter_argv(cwd_lookup_enabled, [str(outside), *_shell_argv("ENTRY")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False
    assert calls == []


def test_ambient_path_hardlink_to_subject_root_executable_is_refused(tmp_path, tmp_path_factory, capsys,
                                                                     cwd_lookup_enabled) -> None:
    subject = _tool_copy(tmp_path, "fakeverifiertool")
    bin_dir = tmp_path_factory.mktemp("path-alias-bin")
    _hardlink_or_skip(subject, bin_dir / subject.name)
    calls = _stub_launch(cwd_lookup_enabled)
    cwd_lookup_enabled.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("PATHALIAS")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False
    assert calls == []


def test_path_candidate_symlink_into_subject_root_is_refused(tmp_path, tmp_path_factory, capsys,
                                                             cwd_lookup_enabled) -> None:
    subject = _tool_copy(tmp_path, "fakeverifiertool")
    bin_dir = tmp_path_factory.mktemp("link-bin")
    try:
        os.symlink(subject, bin_dir / subject.name)
    except OSError:
        pytest.skip("OS_CAPABILITY_GUARD: symbolic link creation unavailable on this host")
    cwd_lookup_enabled.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("LINK")])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["blockers"] == ["RUNNER_TOOL_PATH_NOT_TRUSTED"]
    assert report["execution_attempted"] is False


def test_tool_overwritten_in_place_after_resolution_is_not_launched(tmp_path, tmp_path_factory, capsys,
                                                                    cwd_lookup_enabled, monkeypatch) -> None:
    tool = _tool_copy(tmp_path_factory.mktemp("overwrite-bin"), "fakeverifiertool")
    original = tool.read_bytes()
    resolve = runners._trusted_executable
    outcome: dict[str, str] = {}

    def resolve_then_overwrite(name, root):
        bound = resolve(name, root)
        try:
            with open(tool, "ab") as handle:
                handle.write(b"-tampered-after-resolution")
            outcome["mutation"] = "WRITTEN"
        except OSError as exc:
            # Windows: the bound handle shares read only, so the in-place append is refused.
            if not _is_access_or_sharing_violation(exc):
                raise
            outcome["mutation"] = "DENIED"
        return bound

    monkeypatch.setattr(runners, "_trusted_executable", resolve_then_overwrite)
    calls: list = []
    monkeypatch.setattr(run_module, "capture_run", _completed_capture(lambda: None, calls=calls))
    _adapter_argv(cwd_lookup_enabled, [str(tool), *_shell_argv("OVERWRITE")])
    code, report = _run_adapter(tmp_path, capsys)
    if outcome["mutation"] == "WRITTEN":
        assert code == 2
        assert report["status"] == "UNKNOWN"
        assert report["blockers"] == ["RUNNER_TOOL_IDENTITY_CHANGED"]
        assert report["execution_attempted"] is False
        assert calls == []
    else:
        assert code == 0
        assert len(calls) == 1
        assert tool.read_bytes() == original
        assert Path(calls[0]["command"][0]).resolve() == tool.resolve()


def test_tool_replaced_after_resolution_is_refused_or_held(tmp_path, tmp_path_factory, capsys,
                                                           cwd_lookup_enabled, monkeypatch) -> None:
    tool = _tool_copy(tmp_path_factory.mktemp("replace-bin"), "fakeverifiertool")
    replacement = _tool_copy(tmp_path_factory.mktemp("replacement-bin"), "fakeverifiertool")
    resolve = runners._trusted_executable
    outcome: dict[str, bool] = {}

    def resolve_then_replace(name, root):
        bound = resolve(name, root)
        try:
            os.replace(replacement, tool)
            outcome["replaced"] = True
        except OSError as exc:
            # Windows: the bound handle denies rename of the executable, so the original stays bound.
            # Only the access or sharing refusal is expected; any other error must surface.
            if not _is_access_or_sharing_violation(exc):
                raise
            outcome["replaced"] = False
        return bound

    monkeypatch.setattr(runners, "_trusted_executable", resolve_then_replace)
    calls = _stub_launch(monkeypatch)
    _adapter_argv(cwd_lookup_enabled, [str(tool), *_shell_argv("REPLACE")])
    code, report = _run_adapter(tmp_path, capsys)
    if outcome["replaced"]:
        assert code == 2
        assert report["status"] == "UNKNOWN"
        assert report["blockers"] == ["RUNNER_TOOL_IDENTITY_CHANGED"]
        assert report["execution_attempted"] is False
        assert calls == []
    else:
        # The bound handle denied the replacement, so the launch is the original binary.
        assert code == 0
        assert len(calls) == 1
        assert Path(calls[0]["command"][0]).resolve() == tool.resolve()


def test_ambient_path_reorder_after_lookup_does_not_rebind_tool(tmp_path, tmp_path_factory, capsys,
                                                                cwd_lookup_enabled, monkeypatch) -> None:
    bound_dir = tmp_path_factory.mktemp("bound-bin")
    bound = _tool_copy(bound_dir, "fakeverifiertool")
    rival_dir = tmp_path_factory.mktemp("rival-bin")
    _tool_copy(rival_dir, "fakeverifiertool")
    cwd_lookup_enabled.setenv("PATH", str(bound_dir) + os.pathsep + os.environ["PATH"])
    resolve = runners._trusted_executable

    def lookup_then_reorder(name, root):
        tool = resolve(name, root)
        cwd_lookup_enabled.setenv("PATH", str(rival_dir) + os.pathsep + os.environ["PATH"])
        return tool

    monkeypatch.setattr(runners, "_trusted_executable", lookup_then_reorder)
    calls = _stub_launch(cwd_lookup_enabled)
    _adapter_argv(cwd_lookup_enabled, ["fakeverifiertool", *_shell_argv("BOUND")])
    code, _ = _run_adapter(tmp_path, capsys)
    assert code == 0
    assert len(calls) == 1
    assert Path(calls[0]["command"][0]).resolve() == bound.resolve()


def _is_access_or_sharing_violation(exc: OSError) -> bool:
    """Only the Windows refusal of a write, rename or delete on a file another handle holds.

    Access denied (5) or sharing violation (32), reported as a winerror or as EACCES or EPERM.
    Any other operating system (OS) error is not a denial and must not be treated as one.
    """

    if sys.platform != "win32":
        return False
    return getattr(exc, "winerror", None) in (5, 32) or exc.errno in (errno.EACCES, errno.EPERM)


def _flip_one_byte_restoring_mtime(path: Path) -> None:
    """Same-size in-place byte flip, then the prior modification time restored."""

    before = path.stat()
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    with open(path, "r+b") as handle:
        handle.write(bytes(data))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


def test_same_size_byte_flip_with_restored_mtime_is_denied_or_not_launched(
    tmp_path, tmp_path_factory, capsys, cwd_lookup_enabled, monkeypatch,
) -> None:
    tool = _tool_copy(tmp_path_factory.mktemp("flip-bin"), "fakeverifiertool")
    original = tool.read_bytes()
    resolve = runners._trusted_executable
    outcome: dict[str, str] = {}

    def resolve_then_flip(name, root):
        bound = resolve(name, root)
        try:
            _flip_one_byte_restoring_mtime(tool)
            outcome["mutation"] = "WRITTEN"
        except OSError as exc:
            if not _is_access_or_sharing_violation(exc):
                raise
            outcome["mutation"] = "DENIED"
        return bound

    monkeypatch.setattr(runners, "_trusted_executable", resolve_then_flip)
    calls = _stub_launch(monkeypatch)
    _adapter_argv(cwd_lookup_enabled, [str(tool), *_shell_argv("FLIP")])
    code, report = _run_adapter(tmp_path, capsys)
    assert outcome["mutation"] in {"DENIED", "WRITTEN"}
    if sys.platform == "win32":
        # The held handle's share mode is the mechanism on Windows, so the write must be refused there.
        assert outcome["mutation"] == "DENIED"
    if outcome["mutation"] == "WRITTEN":
        # The mutated bytes are on disk, so the launch must be refused before any process starts.
        assert code == 2
        assert report["status"] == "UNKNOWN"
        assert report["blockers"] == ["RUNNER_TOOL_IDENTITY_CHANGED"]
        assert report["execution_attempted"] is False
        assert calls == []
    else:
        assert code == 0
        assert report["status"] == "PASS"
        assert len(calls) == 1
        assert tool.read_bytes() == original
    # Whichever branch ran, no launch may have started from tampered bytes.
    assert all(Path(call["command"][0]).read_bytes() == original for call in calls)
    binding = report["tool_binding"]
    # Secure Hash Algorithm 256-bit (SHA-256) is the content digest; the report names it verbatim.
    assert binding["content_digest"] == "SHA-256"
    assert binding["executed_image_bytes"] == "UNKNOWN"
    assert binding["atomic_exec_identity"] == "UNKNOWN"


def test_bound_tool_detects_same_size_flip_or_denies_it(tmp_path, tmp_path_factory) -> None:
    tool = _tool_copy(tmp_path_factory.mktemp("bound-unit-bin"), "fakeverifiertool")
    bound = runners._trusted_executable(str(tool), tmp_path)
    try:
        try:
            _flip_one_byte_restoring_mtime(tool)
        except OSError as exc:
            assert _is_access_or_sharing_violation(exc)
            assert bound.still_bound() == "BOUND"
        else:
            # Path identity (device, inode, size, mtime) is unchanged here; only the content digest can see this.
            assert bound.still_bound() == "CHANGED"
    finally:
        bound.close()


def test_content_digest_detects_same_size_flip_when_writes_are_not_refused(tmp_path, tmp_path_factory, monkeypatch) -> None:
    """The digest alone, with no share-mode refusal: the descriptor is opened the POSIX way on every platform."""
    tool = _tool_copy(tmp_path_factory.mktemp("digest-only-bin"), "fakeverifiertool")
    monkeypatch.setattr(runners, "_open_held_executable", lambda path: os.open(path, runners._OPEN_EXECUTABLE))
    bound = runners._trusted_executable(str(tool), tmp_path)
    try:
        _flip_one_byte_restoring_mtime(tool)
        assert bound.still_bound() == "CHANGED"
    finally:
        bound.close()


@pytest.mark.skipif(sys.platform != "win32",
                    reason="OS_CAPABILITY_GUARD: Windows share-mode refusal of rename and delete is not POSIX behavior")
def test_bound_windows_tool_refuses_rename_and_delete(tmp_path, tmp_path_factory) -> None:
    tool = _tool_copy(tmp_path_factory.mktemp("bound-share-bin"), "fakeverifiertool")
    replacement = _tool_copy(tmp_path_factory.mktemp("share-replacement-bin"), "fakeverifiertool")
    bound = runners._trusted_executable(str(tool), tmp_path)
    try:
        with pytest.raises(OSError) as renamed:
            os.replace(replacement, tool)
        assert _is_access_or_sharing_violation(renamed.value)
        with pytest.raises(OSError) as deleted:
            tool.unlink()
        assert _is_access_or_sharing_violation(deleted.value)
    finally:
        bound.close()


# --- F9: directory traversal and lstat uncertainty during detection ----------------------

def test_directory_visit_bound_is_unknown_and_leaks_no_names(tmp_path, tmp_path_factory) -> None:
    outside = tmp_path_factory.mktemp("wide-outside")
    (outside / "outside_secret_module.py").write_text("", encoding="utf-8")
    root = tmp_path / "wide"
    for index in range(12):
        (root / f"branch{index:02d}").mkdir(parents=True)
    result = runners.detect_languages(root, max_directories=5)
    assert result["status"] == "UNKNOWN"
    assert result["capacity_reached"] is True
    assert result["directory_visit_bound"] == 5
    assert "branch" not in json.dumps(result) and "outside_secret" not in json.dumps(result)


def test_deep_directory_chain_is_bounded_and_complete_when_within_bound(tmp_path) -> None:
    deep = tmp_path / "deep"
    for index in range(30):
        deep = deep / f"level{index}"
    deep.mkdir(parents=True)
    (deep / "leaf.py").write_text("", encoding="utf-8")
    complete = runners.detect_languages(tmp_path)
    assert complete["status"] == "PASS"
    assert complete["languages"] == {"python": 1}
    bounded = runners.detect_languages(tmp_path, max_directories=10)
    assert bounded["status"] == "UNKNOWN"
    assert bounded["languages"] == {}
    assert "level" not in json.dumps(bounded)


def test_lstat_failure_on_file_is_unknown_and_not_counted(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    (tmp_path / "hidden_file.py").write_text("", encoding="utf-8")
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if Path(path).name == "hidden_file.py":
            raise PermissionError(13, "denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(runners.os, "lstat", failing)
    result = runners.detect_languages(tmp_path)
    assert result["status"] == "UNKNOWN"
    assert result["unobservable_entry_count"] == 1
    assert result["languages"] == {"python": 1}
    assert "hidden_file" not in json.dumps(result)


def test_lstat_failure_on_directory_is_not_traversed(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    hidden = tmp_path / "hidden_dir"
    hidden.mkdir()
    (hidden / "buried.py").write_text("", encoding="utf-8")
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if Path(path).name == "hidden_dir":
            raise PermissionError(13, "denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(runners.os, "lstat", failing)
    result = runners.detect_languages(tmp_path)
    assert result["status"] == "UNKNOWN"
    assert result["languages"] == {"python": 1}
    assert result["examined_file_count"] == 1
    assert "hidden_dir" not in json.dumps(result)


def test_reparse_attribute_on_directory_is_skipped_not_traversed(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    linked = tmp_path / "linked_dir"
    linked.mkdir()
    (linked / "buried.py").write_text("", encoding="utf-8")
    real_lstat = os.lstat

    def reparse(path, *args, **kwargs):
        if Path(path).name == "linked_dir":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755,
                                   st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(runners.os, "lstat", reparse)
    result = runners.detect_languages(tmp_path)
    assert result["languages"] == {"python": 1}
    assert result["reparse_points_skipped"] == 1
    assert result["status"] == "PASS"


# --- F9: excluded directories are policy exclusions, never silent completeness ----------

def test_excluded_directories_are_counted_and_defeat_whole_repo_completeness(tmp_path) -> None:
    (tmp_path / "main.py").write_text("", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook_script.py").write_text("", encoding="utf-8")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "vendored_module.py").write_text("", encoding="utf-8")
    result = runners.detect_languages(tmp_path)
    # Practical PASS for the declared discovery scope; the excluded trees are named and not inspected.
    assert result["status"] == "PASS"
    assert result["languages"] == {"python": 1}
    assert result["coverage_scope"] == "DECLARED_DISCOVERY_SCOPE"
    assert result["excluded_directories_skipped"] == 2
    assert result["excluded_directory_names_skipped"] == [".git", "node_modules"]
    assert result["whole_repo_complete"] is False
    serialized = json.dumps(result)
    assert "hook_script" not in serialized and "vendored_module" not in serialized and "pkg" not in serialized


def test_repository_without_excluded_directories_is_whole_repo_complete(tmp_path) -> None:
    (tmp_path / "main.py").write_text("", encoding="utf-8")
    result = runners.detect_languages(tmp_path)
    assert result["status"] == "PASS"
    assert result["excluded_directories_skipped"] == 0
    assert result["excluded_directory_names_skipped"] == []
    assert result["whole_repo_complete"] is True


def test_incomplete_detection_is_never_whole_repo_complete(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    (tmp_path / "hidden_file.py").write_text("", encoding="utf-8")
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if Path(path).name == "hidden_file.py":
            raise PermissionError(13, "denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(runners.os, "lstat", failing)
    result = runners.detect_languages(tmp_path)
    assert result["status"] == "UNKNOWN"
    assert result["whole_repo_complete"] is False


def test_scandir_failure_on_directory_is_unknown_and_not_traversed(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    locked = tmp_path / "locked_dir"
    locked.mkdir()
    (locked / "buried.py").write_text("", encoding="utf-8")
    real_scandir = os.scandir

    def failing(path="."):
        if Path(path).name == "locked_dir":
            raise PermissionError(13, "denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(runners.os, "scandir", failing)
    result = runners.detect_languages(tmp_path)
    assert result["status"] == "UNKNOWN"
    assert result["languages"] == {"python": 1}
    assert result["unobservable_entry_count"] == 1
    serialized = json.dumps(result)
    assert "locked_dir" not in serialized and "buried" not in serialized


def test_directory_swapped_after_discovery_is_not_traversed(tmp_path, monkeypatch) -> None:
    (tmp_path / "inside.py").write_text("", encoding="utf-8")
    swapped = tmp_path / "swapped_dir"
    swapped.mkdir()
    (swapped / "buried.py").write_text("", encoding="utf-8")
    real_lstat = os.lstat
    real_scandir = os.scandir
    looks = {"count": 0}
    scanned: list[str] = []

    def lstat(path, *args, **kwargs):
        real = real_lstat(path, *args, **kwargs)
        if Path(path).name == "swapped_dir":
            looks["count"] += 1
            if looks["count"] > 1:
                # Simulates a junction swapped in after discovery: the name now resolves to another identity.
                return SimpleNamespace(st_mode=real.st_mode, st_dev=real.st_dev, st_ino=real.st_ino + 1,
                                       st_size=real.st_size, st_mtime_ns=real.st_mtime_ns, st_file_attributes=0)
        return real

    def scandir(path="."):
        if Path(path).name == "swapped_dir":
            scanned.append(str(path))
        return real_scandir(path)

    monkeypatch.setattr(runners.os, "lstat", lstat)
    monkeypatch.setattr(runners.os, "scandir", scandir)
    result = runners.detect_languages(tmp_path)
    assert scanned == []
    assert result["status"] == "UNKNOWN"
    assert result["languages"] == {"python": 1}
    serialized = json.dumps(result)
    assert "buried" not in serialized and "swapped" not in serialized


# --- F10: a contract or normalization error after an attempted launch is UNKNOWN ---------

@pytest.mark.parametrize(("observation", "blocker"), [
    pytest.param(None, "RUNNER_PROCESS_OBSERVATION_MISSING", id="observation-missing"),
    pytest.param({"result": {"process_started": "MAYBE"}}, "RUNNER_PROCESS_OBSERVATION_INVALID",
                 id="observation-invalid"),
])
def test_receipt_missing_observation_after_launch_is_unknown_not_fail(
    tmp_path, capsys, monkeypatch, observation, blocker,
) -> None:
    _write_python_entry(tmp_path)
    calls: list = []
    receipt = ({"execution": {"exit_code": 0}} if observation is None else
               {"assessment_context": {"refutation_surface": {"parent_process_observation": observation}}})

    def capture(manifest, manifest_dir):
        calls.append(manifest)
        return SimpleNamespace(execution=SimpleNamespace(exit_code=0), to_dict=lambda: receipt)

    monkeypatch.setattr(run_module, "capture_run", capture)
    code, report = _run_python(tmp_path, capsys)
    assert len(calls) == 1
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [blocker]
    assert report["execution_attempted"] is True
    assert report["execution_performed"] is None


def test_backend_protocol_error_after_attempt_is_unknown_not_fail(tmp_path, capsys, monkeypatch) -> None:
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")

    class Backend:
        name = "openshell"

        def load(self):
            def run(_request):
                return "not a result object"

            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    code = main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"])
    report = _report(capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_SANDBOX_PROTOCOL_DIFFERS"]
    assert report["execution_attempted"] is True
    assert report["execution_performed"] is None


def test_contract_error_before_any_launch_stays_fail(tmp_path, capsys, monkeypatch) -> None:
    calls = _stub_launch(monkeypatch)
    _adapter_argv(monkeypatch, [""])
    code, report = _run_adapter(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_ARGUMENT_VECTOR_INVALID"]
    assert report["execution_attempted"] is False
    assert calls == []


@pytest.mark.parametrize("state", ["UNOBSERVABLE", "UNSTABLE_OBSERVATION", "NOT_REGULAR_FILE"])
def test_equal_unobservable_states_never_bind_a_pass(state) -> None:
    observation = {"state": state, "relative_path": "main.py"}
    assert runners._bound_observation(observation, dict(observation)) is False
    observed = {"state": "OBSERVED", "relative_path": "main.py", "sha256": "0" * 64}
    assert runners._bound_observation(observed, dict(observed)) is True
