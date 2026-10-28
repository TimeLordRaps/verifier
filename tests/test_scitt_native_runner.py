"""Bounded native Supply Chain Integrity, Transparency, and Trust (SCITT) capture."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest
from examples.scitt_native_interop import native_runner as runner


ROOT = Path(__file__).resolve().parents[1]
def public_specimen() -> dict[str, bytes]:
    root = ROOT / "examples/scitt_interop"
    return {name: (root / name if name == "artifact.txt" else root / "generated" / name).read_bytes() for name in runner.EXPECTED_SPECIMEN}


def test_fixed_corpus_has_twelve_exact_cases_and_deterministic_mutations() -> None:
    corpus, inputs = runner.build_corpus(public_specimen())
    assert corpus["schema_version"] == "SCITT-NATIVE-CORPUS-1"
    assert len(corpus["cases"]) == len({case["case_id"] for case in corpus["cases"]}) == 12
    assert corpus == runner.build_corpus(public_specimen())[0]
    assert sum(case["expected_accept"] for case in corpus["cases"]) == 3
    assert inputs["inputs/statement-signature-bitflip.cose"][:-1] == inputs["inputs/signed_statement.cose"][:-1]
    assert all(case["input_path"] in inputs and case["public_key_path"] in inputs for case in corpus["cases"])
    assert all(case["leaf_path"] is None or case["leaf_path"] in inputs for case in corpus["cases"])
    assert runner.sha256(inputs["inputs/statement-payload-bitflip.cose"]) == "32b17ec693e95df0b5d212f8e8867b2802f2baf965f07f6bab69d7e958917cd1"


@pytest.mark.parametrize("change", ["changed", "missing", "extra", "wrong_type"])
def test_corpus_rejects_any_unpinned_specimen(change: str) -> None:
    specimen = public_specimen()
    if change == "changed":
        specimen["artifact.txt"] += b"changed"
    elif change == "missing":
        del specimen["receipt.cose"]
    elif change == "extra":
        specimen["other"] = b""
    else:
        specimen["artifact.txt"] = "not bytes"
    with pytest.raises(runner.NativeCaptureError):
        runner.build_corpus(specimen)


def test_bounded_read_and_exclusive_output_refuse_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"exact")
    assert runner.read_regular(path, 5) == b"exact"
    with pytest.raises(runner.NativeCaptureError, match="read bound"):
        runner.read_regular(path, 4)
    with pytest.raises(FileExistsError):
        runner._write_new(path, b"overwrite")
    assert path.read_bytes() == b"exact"
    with pytest.raises(runner.NativeCaptureError):
        runner.read_regular(tmp_path, 100)


@pytest.mark.parametrize("parent_alias", [False, True])
def test_symlink_input_or_parent_is_refused(tmp_path: Path, parent_alias: bool) -> None:
    source = tmp_path / "real"
    source.mkdir()
    (source / "input").write_bytes(b"exact")
    link = tmp_path / "link"
    try:
        link.symlink_to(source if parent_alias else source / "input", target_is_directory=parent_alias)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {type(exc).__name__}")
    with pytest.raises(runner.NativeCaptureError, match="reparse"):
        runner.read_regular(link / "input" if parent_alias else link, 10)


@pytest.mark.parametrize("parent_reparse", [False, True])
def test_reparse_attribute_refusal_without_symlink_creation_privilege(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_reparse: bool) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"exact")
    real = Path.lstat
    selected = tmp_path if parent_reparse else path
    def marked(current, *args, **kwargs):
        info = real(current, *args, **kwargs)
        if current == selected:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", marked)
    with pytest.raises(runner.NativeCaptureError, match="reparse"):
        runner.read_regular(path, 10)


def test_reader_refuses_changed_identity_during_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"before")
    real = runner.os.open
    def replace_before_open(target, flags, *args):
        path.write_bytes(b"different-size")
        return real(target, flags, *args)
    monkeypatch.setattr(runner.os, "open", replace_before_open)
    with pytest.raises(runner.NativeCaptureError, match="changed before"):
        runner.read_regular(path, 100)


def test_binary_channels_remain_byte_exact_and_visible(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    program = "import os;os.write(1,b'one\\r\\ntwo\\xff');os.write(2,b'err\\x00\\r\\n')"
    code, stop, stdout, stderr = runner._run_process("binary", [sys.executable, "-I", "-B", "-u", "-c", program], tmp_path)
    assert (code, stop, stdout, stderr) == (0, None, b"one\r\ntwo\xff", b"err\x00\r\n")
    visible = capsys.readouterr().out
    assert "START binary" in visible and "END binary" in visible
    assert "[binary/stdout]" in visible and "[binary/stderr]" in visible


@pytest.mark.parametrize("channel", [1, 2])
def test_output_flood_stops_at_per_channel_cap(tmp_path: Path, channel: int) -> None:
    code, stop, stdout, stderr = runner._run_process("overflow", [sys.executable, "-I", "-B", "-u", "-c", f"import os;os.write({channel},b'x'*4096)"], tmp_path, output_limit=17)
    assert stop == "OUTPUT_LIMIT"
    assert len(stdout if channel == 1 else stderr) == 17
    assert len(stderr if channel == 1 else stdout) == 0


def test_process_timeout_is_bounded_and_not_semantic_rejection(tmp_path: Path) -> None:
    started = time.monotonic()
    code, stop, stdout, stderr = runner._run_process("timeout", [sys.executable, "-I", "-B", "-u", "-c", "import time;time.sleep(10)"], tmp_path, timeout=0.1)
    assert stop == "TIMEOUT"
    assert time.monotonic() - started < 3
    assert stdout == stderr == b""


def test_launch_error_retains_no_fabricated_native_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*args, **kwargs):
        raise PermissionError("path must not leak")
    monkeypatch.setattr(runner.subprocess, "Popen", denied)
    assert runner._run_process("denied", ["unavailable"], tmp_path) == (None, "LAUNCH_ERROR", b"", b"")


def test_pipe_read_failure_is_operational(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(io.BytesIO):
        def read(self, size=-1):
            raise OSError("broken pipe")
    class Process:
        stdout = Broken()
        stderr = io.BytesIO(b"")
        def poll(self):
            return 0
        def wait(self, timeout):
            return 0
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *args, **kwargs: Process())
    assert runner._run_process("pipe-error", ["stub"], tmp_path)[1] == "LAUNCH_ERROR"


@pytest.mark.parametrize("failure", [KeyboardInterrupt, RuntimeError])
@pytest.mark.parametrize("phase", ["constructor", "second-constructor", "start", "monitor"])
def test_observer_cancellation_kills_and_reaps_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[BaseException], phase: str,
) -> None:
    processes = []
    real_popen = runner.subprocess.Popen
    def track(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process
    def interrupted(*args, **kwargs):
        raise failure("observer interrupted")
    monkeypatch.setattr(runner.subprocess, "Popen", track)
    if phase == "constructor":
        monkeypatch.setattr(runner.threading, "Thread", interrupted)
    elif phase == "second-constructor":
        real_thread = runner.threading.Thread
        created = []
        def second_interrupted(*args, **kwargs):
            if created:
                return interrupted()
            thread = real_thread(*args, **kwargs)
            created.append(thread)
            return thread
        monkeypatch.setattr(runner.threading, "Thread", second_interrupted)
    elif phase == "start":
        monkeypatch.setattr(runner.threading.Thread, "start", interrupted)
    else:
        monkeypatch.setattr(runner.queue.Queue, "get", interrupted)
    try:
        with pytest.raises(failure, match="observer interrupted"):
            runner._run_process("cancelled", [sys.executable, "-I", "-B", "-u", "-c", "import time;time.sleep(30)"], tmp_path)
        assert len(processes) == 1
        assert processes[0].poll() is not None, "cancelled observer left direct child alive"
        assert processes[0].stdout.closed and processes[0].stderr.closed
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def snapshot() -> dict:
    return {"python_version": "3.12.8", "python_executable_sha256": runner.sha256(runner.read_regular(Path(sys.executable), runner.MAX_BINARY_BYTES)),
        "python_distributions": dict(runner.PYTHON_DISTRIBUTION_PINS), "python_source_sha256": dict(runner.PYTHON_SOURCE_PINS)}


def test_capture_records_all_operational_failures_without_verdicts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    go = tmp_path / "checker.exe"
    go.write_bytes(b"host-selected test executable bytes")
    observed = snapshot()
    monkeypatch.setattr(runner, "_python_snapshot", lambda *args: dict(observed))
    calls = []
    def simulated(name, arguments, cwd):
        calls.append((name, arguments))
        return None, "TIMEOUT", b"partial\r\n", b""
    monkeypatch.setattr(runner, "_run_process", simulated)
    output = tmp_path / "capture"
    runner.capture_comparison(go, runner.sha256(go.read_bytes()), specimen_dir=ROOT / "examples/scitt_interop", output_dir=output)
    records = json.loads((output / "observations.json").read_bytes())
    assert len(records["observations"]) == len(calls) == 24
    assert all(item["stop_reason"] == "TIMEOUT" and item["exit_code"] is None for item in records["observations"])
    assert all("verdict" not in item and "status" not in item for item in records["observations"])
    for item in records["observations"]:
        assert (output / item["stdout_path"]).read_bytes() == b"partial\r\n"
        assert item["stdout_sha256"] == runner.sha256(b"partial\r\n")
    runtime = json.loads((output / "runtime.json").read_bytes())
    assert runtime["source_state_unchanged"] is True
    assert runtime["runner_sha256"] == runner.sha256(Path(runner.__file__).read_bytes())
    assert str(tmp_path) not in json.dumps(runtime)
    assert all(arguments[1:5] == ["-I", "-B", "-u", "-m"] for name, arguments in calls if name.endswith("-python"))
    with pytest.raises(FileExistsError):
        runner.capture_comparison(go, runner.sha256(go.read_bytes()), specimen_dir=ROOT / "examples/scitt_interop", output_dir=output)


def test_postflight_source_drift_sets_global_unknown_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    go = tmp_path / "checker.exe"
    go.write_bytes(b"test binary")
    initial = snapshot()
    snapshots = 0
    def changing(*args):
        nonlocal snapshots
        snapshots += 1
        return dict(initial) if snapshots < 3 else None
    monkeypatch.setattr(runner, "_python_snapshot", changing)
    calls = []
    def native(name, arguments, cwd):
        calls.append(name)
        return 0, None, b'{"valid":true}', b""
    monkeypatch.setattr(runner, "_run_process", native)
    output = tmp_path / "capture"
    runner.capture_comparison(go, runner.sha256(go.read_bytes()), specimen_dir=ROOT / "examples/scitt_interop", output_dir=output)
    records = json.loads((output / "observations.json").read_bytes())["observations"]
    assert len(records) == 24 and len(calls) == 1
    assert all(item["stop_reason"] == "LAUNCH_ERROR" for item in records)
    assert json.loads((output / "runtime.json").read_bytes())["source_state_unchanged"] is False


def test_wrong_host_executable_digest_never_creates_output(tmp_path: Path) -> None:
    go = tmp_path / "checker.exe"
    go.write_bytes(b"test binary")
    output = tmp_path / "capture"
    with pytest.raises(runner.NativeCaptureError, match="host-selected digest"):
        runner.capture_comparison(go, "0" * 64, specimen_dir=ROOT / "examples/scitt_interop", output_dir=output)
    assert not output.exists()


def test_public_command_parses_explicit_host_authority(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = []
    monkeypatch.setattr(runner, "capture_comparison", lambda *args, **kwargs: calls.append((args, kwargs)))
    go, output = tmp_path / "checker", tmp_path / "capture"
    assert runner.main(["--go-checker", str(go), "--expected-go-sha256", "a" * 64,
                        "--output-dir", str(output)]) == 0
    assert calls == [((go, "a" * 64), {"specimen_dir": ROOT / "examples/scitt_interop", "output_dir": output})]
    with pytest.raises(SystemExit) as stopped:
        runner.main(["--help"])
    assert stopped.value.code == 0
    assert len(calls) == 1


def test_reader_requests_nonblocking_open_when_available(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"exact")
    real = runner.os.open
    observed = []
    flag = getattr(runner.os, "O_NONBLOCK", 0x40000000)
    monkeypatch.setattr(runner.os, "O_NONBLOCK", flag, raising=False)
    def inspect_open(target, flags, *args):
        observed.append(flags)
        return real(target, flags & ~flag, *args)
    monkeypatch.setattr(runner.os, "open", inspect_open)
    assert runner.read_regular(path, 5) == b"exact"
    assert observed and observed[0] & flag
