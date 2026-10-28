"""Language-neutral Verifier Standard (VSTD) runner boundary regressions.

Terminology: American Standard Code for Information Interchange (ASCII);
Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

from verifier.runtime import language_runners as runners
from verifier.runtime.public_cli import main

# Bounded printable ASCII: the only vocabulary a reason or next_action may carry.
_GUIDANCE_TEXT = re.compile(r"[ -~]{1,240}")


def _assert_guided(report: dict) -> None:
    for key in ("reason", "next_action"):
        assert isinstance(report.get(key), str), (key, report.get(key))
        assert _GUIDANCE_TEXT.fullmatch(report[key]), (key, report[key])


def _runner_process_observation(report: dict) -> dict:
    observation = report["receipt"]["assessment_context"]["refutation_surface"].get(
        "parent_process_observation"
    )
    assert isinstance(observation, dict)
    return observation


def test_runner_catalog_is_reachable_and_distinguishes_implemented_targets(capsys) -> None:
    assert main(["runner", "catalog", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["default_language"] == "python"
    assert len([r for r in report["languages"] if r["cohort"] == "top24-extension-target"]) == 24
    assert {r["language"] for r in report["languages"]} >= {"python", "lisp", "sql", "javascript", "scratch", "typescript"}
    top24 = [r for r in report["languages"] if r["cohort"] == "top24-extension-target"]
    assert sum(r["runner_status"] == "EXTENSION_AVAILABLE" for r in top24) == 23
    assert {r["language"] for r in top24 if r["runner_status"] == "NOT_IMPLEMENTED"} == {
        "classic-visual-basic"
    }
    assert sum(r["runner_status"] == "EXTENSION_AVAILABLE" for r in report["languages"]) == 25
    assert all(r["qualification"] == "NOT_ESTABLISHED" for r in report["languages"])


def test_all_implemented_top24_names_are_admitted_only_by_explicit_selection(
    tmp_path, capsys, monkeypatch
) -> None:
    implemented = {
        language: suffixes[0]
        for language, suffixes in runners._TARGETS
        if language != "classic-visual-basic"
    }
    monkeypatch.setattr(runners, "find_spec", lambda package: object())
    assert {item.name for item in runners._extensions()} >= set(implemented)

    for language, suffix in sorted(implemented.items()):
        entry = tmp_path / f"subject{suffix}"
        entry.write_text("not executed", encoding="utf-8")
        assert main(
            [
                "runner",
                "plan",
                entry.name,
                "--root",
                str(tmp_path),
                "--language",
                language,
                "--trusted-local",
                "--json",
            ]
        ) == 2
        report = json.loads(capsys.readouterr().out)
        assert report["language"] == language
        assert report["selection"] == "EXPLICIT"
        assert report["extension_status"] == "INSTALLED_NOT_LOADED"
        assert report["execution_performed"] is False


def test_detection_does_not_import_or_execute_project_and_keeps_ambiguity(tmp_path, capsys) -> None:
    (tmp_path / "test.py").write_text("raise RuntimeError('do not import')", encoding="utf-8")
    (tmp_path / "code.m").write_text("ambiguous", encoding="utf-8")
    assert main(["runner", "detect", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result["languages"]) == {"python", "matlab", "objective-c"}
    assert result["ambiguous_file_count"] == 1
    assert result["execution_performed"] is False


def test_python_remains_default_even_for_javascript_repo(tmp_path, capsys) -> None:
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    assert main(["runner", "plan", "main.js", "--root", str(tmp_path), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["language"] == "python"
    assert "RUNNER_LANGUAGE_SELECTION_DIFFERS" in result["blockers"]


def test_missing_extension_is_unknown_not_python_fallback(tmp_path, capsys, monkeypatch) -> None:
    from verifier.runtime import language_runners as runners
    monkeypatch.setattr(runners, "_extensions", lambda: [])
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    assert main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["execution_performed"] is False
    assert "RUNNER_EXTENSION_NOT_INSTALLED" in report["blockers"]


def test_conflicting_explicit_language_adapters_are_refused_without_loading(
    tmp_path, capsys, monkeypatch
) -> None:
    loaded: list[str] = []

    class Extension:
        name = "javascript"

        def __init__(self, label: str) -> None:
            self.label = label

        def load(self):
            loaded.append(self.label)
            pytest.fail("ambiguous extensions must not load")

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension("one"), Extension("two")])
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    assert main(
        [
            "runner", "run", "main.js", "--language", "javascript", "--trusted-local",
            "--root", str(tmp_path), "--json",
        ]
    ) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_EXTENSION_SELECTION_AMBIGUOUS"]
    assert report["execution_performed"] is False
    assert loaded == []


def test_malformed_extension_response_is_closed_before_process_launch(
    tmp_path, capsys, monkeypatch
) -> None:
    class Extension:
        name = "javascript"

        def load(self):
            return lambda request: {
                "schema_version": runners.PROTOCOL,
                "language": request["language"],
                "argv": "node main.js",
            }

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    assert main(
        [
            "runner", "run", "main.js", "--language", "javascript", "--trusted-local",
            "--root", str(tmp_path), "--json",
        ]
    ) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_ARGUMENT_VECTOR_INVALID"]
    assert report["execution_attempted"] is False
    assert report["receipt"] is None


@pytest.mark.parametrize("kind,profile,corrigibility", [
    ("AGENT", "agent-open-ended", "NOT_ASSUMED_OPEN_ENDED"),
    ("MODEL", "model-corrigibility", "REQUIRED_NOT_ESTABLISHED"),
    ("BOT", "bot-isolated", "REQUIRED_NOT_ESTABLISHED"),
    ("SIM", "sim-contained", "CONDITIONAL_REQUIRES_REASON"),
])
def test_object_profiles_cannot_fall_back_to_unsandboxed_process(tmp_path, capsys, kind, profile, corrigibility) -> None:
    (tmp_path / "main.py").write_text("raise RuntimeError('must not launch')", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--object-kind", kind, "--trusted-local",
                 "--root", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["profile"]["name"] == profile
    assert report["profile"]["corrigibility"] == corrigibility
    assert report["execution_performed"] is False
    assert "RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED" in report["blockers"]


def test_basic_python_process_requires_explicit_trusted_local_selection(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text("print('runner-ok')", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--json"]) == 2
    assert not json.loads(capsys.readouterr().out)["execution_performed"]
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--trusted-local", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    observation = _runner_process_observation(result)
    assert result["execution_performed"] is True
    assert observation["result"]["process_started"] == "YES"
    assert observation["result"]["outcome"] == "SUCCESS"
    assert result["execution_performed"] is (
        observation["result"]["process_started"] == "YES"
    )
    assert result["receipt"]["execution"]["exit_code"] == 0
    assert "runner-ok" in result["receipt"]["execution"]["stdout_snippet"]
    assert result["tool_binding"] == {
        "scope": "host_outside_subject_root",
        "identity_checks": ["pre_launch", "post_run"],
        "content_digest": "SHA-256",
        "content_checks": ["pre_launch", "post_run"],
        "handle_held_during_run": True,
        "write_rename_delete_refusal": "SHARE_MODE_READ_ONLY" if sys.platform == "win32" else "NOT_ENFORCED",
        "executed_image_bytes": "UNKNOWN",
        "atomic_exec_identity": "UNKNOWN",
    }
    assert "inherited-environment" in observation["unobserved"]
    assert result["sandbox_status"] == "NOT_ESTABLISHED"
    assert result["obligation_status"] == "UNKNOWN"


@pytest.mark.parametrize(
    ("process_started", "expected_execution_performed"),
    (("NO", False), ("UNKNOWN", None)),
)
def test_basic_runner_derives_execution_performed_from_parent_observation(
    tmp_path,
    capsys,
    monkeypatch,
    process_started,
    expected_execution_performed,
) -> None:
    from verifier.core import run as run_module
    from verifier.core.run_process_observation import (
        begin_parent_process_observation,
        observe_indeterminate_execution_error,
        observe_missing_input_no_launch,
        prepare_parent_process_observation,
    )

    (tmp_path / "main.py").write_text(
        "print('must not be represented as started')", encoding="utf-8"
    )

    def fake_capture(manifest, manifest_dir):
        launch_factory = (
            prepare_parent_process_observation
            if process_started == "NO"
            else begin_parent_process_observation
        )
        launch = launch_factory(
            argv=manifest["command"],
            declared_cwd=manifest["cwd"],
            resolved_cwd=Path(manifest_dir),
            timeout_seconds=manifest["timeout_seconds"],
        )
        observation = (
            observe_missing_input_no_launch(launch)
            if process_started == "NO"
            else observe_indeterminate_execution_error(
                launch, RuntimeError("fixture execution state is indeterminate")
            )
        )
        data = {
            "assessment_context": {
                "refutation_surface": {
                    "parent_process_observation": observation,
                }
            }
        }
        return SimpleNamespace(
            execution=SimpleNamespace(exit_code=None),
            to_dict=lambda: data,
        )

    monkeypatch.setattr(run_module, "capture_run", fake_capture)
    assert main(
        [
            "runner",
            "run",
            "main.py",
            "--root",
            str(tmp_path),
            "--trusted-local",
            "--json",
        ]
    ) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["execution_attempted"] is True
    assert report["execution_performed"] is expected_execution_performed
    assert (
        _runner_process_observation(report)["result"]["process_started"]
        == process_started
    )
    _assert_guided(report)
    assert report["status"] == "UNKNOWN"
    assert "not established" in report["reason"]


def test_continuity_and_training_cannot_use_basic_process_profile(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text("print('should not execute')", encoding="utf-8")
    for flag in (["--continuity-required"], ["--activity", "train"]):
        assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--trusted-local", "--json", *flag]) == 2
        result = json.loads(capsys.readouterr().out)
        assert result["execution_performed"] is False


def test_runner_cannot_select_entry_outside_root(tmp_path, capsys) -> None:
    assert main(["runner", "plan", "../external.py", "--root", str(tmp_path), "--json"]) == 1
    assert "RUNNER_ENTRY_OUTSIDE_ROOT" in json.loads(capsys.readouterr().out)["blockers"]


def test_extension_is_only_loaded_for_explicit_admitted_execution(tmp_path, capsys, monkeypatch) -> None:
    from verifier.runtime import language_runners as runners
    calls = []
    adapter_code = (
        "import subprocess, sys; "
        "raise SystemExit(subprocess.run([sys.executable, '-B', '-c', "
        "\"print('descendant-target')\"]).returncode)"
    )
    adapter_argv = [sys.executable, "-B", "-c", adapter_code]

    class Extension:
        name = "test-language"

        def load(self):
            calls.append("loaded")

            def command(request):
                assert request["schema_version"] == runners.PROTOCOL
                assert request["language"] == "test-language"
                # This is a protocol test adapter, not a real foreign-language runner.
                return {"schema_version": runners.PROTOCOL, "language": "test-language",
                        "argv": adapter_argv}

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])
    (tmp_path / "main.test-language").write_text("native declaration", encoding="utf-8")
    base = ["main.test-language", "--language", "test-language", "--root", str(tmp_path), "--json"]
    assert main(["runner", "plan", *base, "--trusted-local"]) == 2
    assert json.loads(capsys.readouterr().out)["extension_status"] == "INSTALLED_NOT_LOADED"
    assert calls == []
    assert main(["runner", "run", *base, "--sandbox", "openshell", "--trusted-local"]) == 2
    assert json.loads(capsys.readouterr().out)["execution_performed"] is False
    assert calls == []
    assert main(["runner", "run", *base, "--trusted-local"]) == 0
    report = json.loads(capsys.readouterr().out)
    observation = _runner_process_observation(report)
    assert report["execution_performed"] is True
    assert report["extension_status"] == "LOADED"
    assert calls == ["loaded"]
    assert observation["launch"]["argv"] == adapter_argv
    assert observation["result"]["process_started"] == "YES"
    assert "descendants" in observation["unobserved"]
    assert "not a whole HARNESS observation" in observation["claim_boundary"]
    assert set(observation) == {
        "schema_version",
        "launch",
        "result",
        "unobserved",
        "claim_boundary",
        "inner_digest",
    }
    assert "descendant-target" in report["receipt"]["execution"]["stdout_snippet"]


def test_detection_capacity_is_unknown_not_complete(tmp_path) -> None:
    from verifier.runtime.language_runners import detect_languages
    (tmp_path / "a.py").write_text("", encoding="utf-8")
    (tmp_path / "b.js").write_text("", encoding="utf-8")
    result = detect_languages(tmp_path, max_files=1)
    assert result["status"] == "UNKNOWN"
    assert result["capacity_reached"] is True


class _UnclassifiedError(Exception):
    """Not in any classified branch, so it must not escape the runner boundary."""


def _javascript_adapter_raising(monkeypatch, error: BaseException) -> None:
    from verifier.runtime import language_runners as runners

    class Extension:
        name = "javascript"

        def load(self):
            def command(request):
                raise error

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])


def _run_javascript(tmp_path, capsys) -> tuple[int, dict]:
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    code = main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(tmp_path), "--json"])
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("tool", ["node", "gcc", "g++", "sqlite3", "gfortran", "sbcl", "swipl"])
def test_adapter_toolchain_missing_reports_exact_unknown_tool_blocker(tmp_path, capsys, monkeypatch, tool) -> None:
    _javascript_adapter_raising(monkeypatch, FileNotFoundError(f"RUNNER_TOOLCHAIN_MISSING:{tool}"))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [f"RUNNER_TOOLCHAIN_MISSING:{tool}"]
    assert report["execution_attempted"] is False
    assert report["execution_performed"] is False


@pytest.mark.parametrize("message", [
    pytest.param("RUNNER_TOOLCHAIN_MISSING:", id="empty-token"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING", id="no-separator"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:../../gcc", id="traversal"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:C:" "\\" "tools" "\\" "gcc", id="drive-path"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:/usr/bin/gcc", id="absolute-path"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc.exe", id="extension-suffix"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:-gcc", id="option-like"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc\nRUNNER_ENTRY_MISSING", id="injected-code"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc\x00", id="nul"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc\x1b[31m", id="ansi-escape"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc status=PASS", id="prose"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:g\u0441c", id="cyrillic-homoglyph"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc\u202e", id="bidi-override"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:" + "a" * 33, id="oversize-token"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:" + "a" * 100_000, id="unbounded-token"),
])
def test_hostile_toolchain_token_never_reaches_blocker_ids(tmp_path, capsys, monkeypatch, message) -> None:
    _javascript_adapter_raising(monkeypatch, FileNotFoundError(message))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]
    assert report["execution_performed"] is False


@pytest.mark.parametrize("error", [
    pytest.param(FileNotFoundError(2, "RUNNER_TOOLCHAIN_MISSING:gcc"), id="errno-form"),
    pytest.param(PermissionError("RUNNER_TOOLCHAIN_MISSING:gcc"), id="wrong-oserror-type"),
    pytest.param(OSError("RUNNER_TOOLCHAIN_MISSING:gcc"), id="base-oserror"),
    pytest.param(TimeoutError("/var/tmp/secret/gcc"), id="other-resource-path"),
])
def test_other_resource_errors_remain_generic(tmp_path, capsys, monkeypatch, error) -> None:
    _javascript_adapter_raising(monkeypatch, error)
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]


@pytest.mark.parametrize("message", [
    pytest.param("RUNNER_ENTRY_MISSING\nRUNNER_FAKE", id="injected-line"),
    pytest.param("RUNNER_FAKE_CODE", id="unlisted-code"),
    pytest.param("RUNNER_TOOLCHAIN_MISSING:gcc", id="toolchain-token-outside-os-error"),
    pytest.param("RUNNER_ENTRY_OUTSIDE_ROOT/../../x", id="path-suffix"),
    pytest.param("RUNNER_" + "A" * 5000, id="unbounded-code"),
])
def test_contract_exception_text_cannot_inject_blocker_ids(tmp_path, capsys, monkeypatch, message) -> None:
    _javascript_adapter_raising(monkeypatch, ValueError(message))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_CONTRACT_REJECTED"]
    assert report["execution_performed"] is False


def test_listed_extension_contract_code_is_preserved_exactly(tmp_path, capsys, monkeypatch) -> None:
    _javascript_adapter_raising(monkeypatch, ValueError("RUNNER_DIALECT_UNSUPPORTED"))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 1
    assert report["blockers"] == ["RUNNER_DIALECT_UNSUPPORTED"]


@pytest.mark.parametrize("error", [
    pytest.param(_UnclassifiedError("RUNNER_TOOLCHAIN_MISSING:GCC"), id="uppercase-token-text"),
    pytest.param(Exception("RUNNER_ENTRY_MISSING"), id="base-exception"),
])
def test_unclassified_adapter_exception_is_closed_unknown_report(tmp_path, capsys, monkeypatch, error) -> None:
    _javascript_adapter_raising(monkeypatch, error)
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_EXCEPTION_UNCLASSIFIED"]
    assert report["execution_performed"] is False


def test_absent_language_package_is_not_installed_without_import(tmp_path, capsys, monkeypatch) -> None:
    from verifier.runtime import language_runners as runners
    monkeypatch.setattr(runners, "find_spec", lambda name: None)
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["blockers"] == ["RUNNER_EXTENSION_NOT_INSTALLED"]
    assert report["execution_performed"] is False


def test_toolchain_failure_never_reaches_sandbox_backend_lookup(tmp_path, capsys, monkeypatch) -> None:
    from verifier.runtime import language_runners as runners
    probes = []
    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: probes.append("probed") or [])
    _javascript_adapter_raising(monkeypatch, FileNotFoundError("RUNNER_TOOLCHAIN_MISSING:node"))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["blockers"] == ["RUNNER_TOOLCHAIN_MISSING:node"]
    assert probes == []


@pytest.mark.parametrize("argv,expected_code,expected_status", [
    (["runner", "catalog", "--json"], 0, "PASS"),
    (["runner", "detect", "DETECT_ROOT", "--json"], 0, "PASS"),
    (["runner", "detect", "MISSING_ROOT", "--json"], 2, "UNKNOWN"),
    (["runner", "plan", "main.py", "--root", "ROOT", "--json"], 2, "UNKNOWN"),
    (["runner", "plan", "main.py", "--root", "ROOT", "--trusted-local", "--json"], 2, "UNKNOWN"),
    (["runner", "run", "main.py", "--root", "ROOT", "--trusted-local", "--json"], 0, "PASS"),
    (["runner", "run", "fail.py", "--root", "ROOT", "--trusted-local", "--json"], 1, "FAIL"),
    (["runner", "run", "main.py", "--root", "ROOT", "--object-kind", "MODEL", "--trusted-local", "--json"], 2, "UNKNOWN"),
    (["runner", "run", "../external.py", "--root", "ROOT", "--json"], 1, "FAIL"),
    (["runner", "run", "main.py", "--root", "ROOT", "--trusted-local", "--timeout", "0", "--json"], 1, "FAIL"),
])
def test_every_plan_and_run_outcome_carries_bounded_reason_and_next_action(
    tmp_path, capsys, argv, expected_code, expected_status,
) -> None:
    (tmp_path / "main.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "fail.py").write_text("raise SystemExit(3)", encoding="utf-8")
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    detect_root = tmp_path / "detect"
    detect_root.mkdir()
    (detect_root / "a.py").write_text("", encoding="utf-8")
    substitutions = {"ROOT": str(tmp_path), "DETECT_ROOT": str(detect_root),
                     "MISSING_ROOT": str(tmp_path / "missing")}
    argv = [substitutions.get(item) or item for item in argv]
    assert main(argv) == expected_code
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == expected_status
    _assert_guided(report)
    if expected_status == "PASS" and argv[1] == "run":
        assert report["sandbox_status"] == "NOT_ESTABLISHED"
        assert report["obligation_status"] == "UNKNOWN"
        assert report["polished"] is False


def test_process_pass_next_action_claims_no_obligation_or_conformance(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text("print('ok')", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--trusted-local", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["next_action"].startswith("No runner repair is required")
    assert "not" in report["next_action"]
    assert "obligation" in report["next_action"]
    assert "conformance" in report["next_action"]


@pytest.mark.parametrize("status,code", [("PASS", 0), ("FAIL", 1), ("UNKNOWN", 2)])
def test_optional_backend_outcomes_without_blockers_are_guided(tmp_path, capsys, monkeypatch, status, code) -> None:
    class Backend:
        name = "openshell"

        def load(self):
            def run(request):
                return {"schema_version": "verifier-openshell-result-1", "status": status,
                        "execution_performed": status != "UNKNOWN", "blockers": []}
            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"]) == code
    report = json.loads(capsys.readouterr().out)
    _assert_guided(report)
    if status == "PASS":
        assert report["next_action"].startswith("No runner repair is required")
        assert "obligation" in report["next_action"]
    assert "trusted-local" not in report["reason"]


def test_guidance_table_is_closed_and_bounded() -> None:
    assert set(runners._BLOCKER_GUIDANCE) == runners._BLOCKER_CODES
    for reason, action in runners._BLOCKER_GUIDANCE.values():
        for text in (reason, action):
            assert _GUIDANCE_TEXT.fullmatch(text), text
            assert len(text) <= 180, text


@pytest.mark.parametrize("code", sorted(runners._BLOCKER_CODES))
def test_each_closed_blocker_code_is_actionable_in_report(code) -> None:
    report = runners._with_guidance({"status": "FAIL", "blockers": [code], "language": "python"}, "process")
    assert report["reason"] == runners._BLOCKER_GUIDANCE[code][0]
    assert report["next_action"] == runners._BLOCKER_GUIDANCE[code][1]
    _assert_guided(report)


def test_toolchain_guidance_names_only_the_validated_tool(tmp_path, capsys, monkeypatch) -> None:
    _javascript_adapter_raising(monkeypatch, FileNotFoundError("RUNNER_TOOLCHAIN_MISSING:gcc"))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert "'gcc'" in report["reason"]
    assert "'gcc'" in report["next_action"]
    assert "PATH" in report["next_action"]


@pytest.mark.parametrize("token", [
    pytest.param("../../gcc", id="traversal"),
    pytest.param("C:" "\\" "tools" "\\" "gcc", id="drive-qualified"),
    pytest.param("gcc\x1b[31m", id="ansi-escape"),
    pytest.param("gcc status=PASS", id="prose"),
    pytest.param("a" * 33, id="oversize-token"),
])
def test_hostile_toolchain_token_is_never_echoed_into_guidance(tmp_path, capsys, monkeypatch, token) -> None:
    _javascript_adapter_raising(monkeypatch, FileNotFoundError("RUNNER_TOOLCHAIN_MISSING:" + token))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["blockers"] == ["RUNNER_RESOURCE_UNAVAILABLE"]
    _assert_guided(report)
    assert token not in report["reason"] + report["next_action"]


def test_missing_language_adapter_names_exact_install_command(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(runners, "_extensions", lambda: [])
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 2
    assert report["blockers"] == ["RUNNER_EXTENSION_NOT_INSTALLED"]
    assert "python -m pip install ./extensions/languages" in report["next_action"]
    assert "vstd-language-runners" in report["next_action"]


def test_unsupported_language_gets_no_install_extra(tmp_path, capsys) -> None:
    (tmp_path / "main.rb").write_text("puts 1", encoding="utf-8")
    assert main(["runner", "run", "main.rb", "--language", "ruby", "--trusted-local",
                 "--root", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["blockers"] == ["RUNNER_EXTENSION_NOT_INSTALLED"]
    assert "pip install" not in report["next_action"]
    assert "EXTENSION_AVAILABLE" in report["next_action"]


def test_missing_openshell_backend_names_optional_path(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [])
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["blockers"] == ["RUNNER_SANDBOX_EXTENSION_NOT_INSTALLED"]
    assert "./extensions/openshell" in report["next_action"]
    assert "vstd-openshell" in report["next_action"]


@pytest.mark.parametrize("kind", ["AGENT", "MODEL", "BOT", "SIM"])
def test_nonbasic_profile_guidance_names_optional_sandbox_path(tmp_path, capsys, kind) -> None:
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--object-kind", kind, "--trusted-local",
                 "--root", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["blockers"][0] == "RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED"
    assert "--sandbox openshell" in report["next_action"]
    assert "--sandbox-config" in report["next_action"]
    assert "never satisfies" in report["next_action"]


@pytest.mark.parametrize("blockers,expected", [
    (["RUNNER_SANDBOX_CONFIG_FIELDS"], ["RUNNER_SANDBOX_CONFIG_FIELDS"]),
    (["RUNNER_FAKE_CODE\nRUNNER_ENTRY_MISSING"], ["RUNNER_SANDBOX_PROTOCOL_DIFFERS"]),
    (["RUNNER_SANDBOX_CONFIG_FIELDS", "x" * 500], ["RUNNER_SANDBOX_CONFIG_FIELDS", "RUNNER_SANDBOX_PROTOCOL_DIFFERS"]),
])
def test_backend_blockers_are_closed_vocabulary_only(tmp_path, capsys, monkeypatch, blockers, expected) -> None:
    class Backend:
        name = "openshell"

        def load(self):
            def run(request):
                return {"schema_version": "verifier-openshell-result-1", "status": "UNKNOWN",
                        "execution_performed": False, "blockers": blockers}
            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["blockers"] == expected
    assert report["execution_attempted"] is True
    # The receipt keeps the backend result verbatim by design; only the closed fields are guaranteed.
    assert "RUNNER_FAKE" not in json.dumps([report["blockers"], report["reason"], report["next_action"]])
    _assert_guided(report)


@pytest.mark.parametrize("value", [object(), float("nan")])
def test_unserializable_backend_receipt_degrades_to_closed_unknown(tmp_path, capsys, monkeypatch, value) -> None:
    class Backend:
        name = "openshell"

        def load(self):
            def run(request):
                return {"schema_version": "verifier-openshell-result-1", "status": "PASS",
                        "execution_performed": True, "blockers": [], "unserializable": value}
            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell",
                 "--sandbox-config", str(config), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_EXCEPTION_UNCLASSIFIED"]
    assert report["execution_performed"] is None
    assert report["sandbox_status"] == "NOT_ESTABLISHED"
    assert report["obligation_status"] == "UNKNOWN"
    assert report["polished"] is False
    _assert_guided(report)


class _HostileArgsValueError(ValueError):
    """Classified by type, but its message accessor itself raises."""

    @property
    def args(self):
        raise RuntimeError("hostile accessor")


def test_hostile_exception_accessor_cannot_escape_runner_boundary(tmp_path, capsys, monkeypatch) -> None:
    _javascript_adapter_raising(monkeypatch, _HostileArgsValueError("RUNNER_ENTRY_MISSING"))
    code, report = _run_javascript(tmp_path, capsys)
    assert code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == ["RUNNER_CONTRACT_REJECTED"]
    _assert_guided(report)


@pytest.mark.parametrize("error", [
    pytest.param(ValueError("RUNNER_" + "A" * 100_000), id="unbounded-contract"),
    pytest.param(_UnclassifiedError("/var/tmp/secret\x1b[2J" + "z" * 100_000), id="unbounded-unclassified"),
])
def test_hostile_message_cannot_inflate_report_output(tmp_path, capsys, monkeypatch, error) -> None:
    _javascript_adapter_raising(monkeypatch, error)
    _run_javascript(tmp_path, capsys)
    out = capsys.readouterr().out
    assert len(out) < 8000
    assert "secret" not in out and "\x1b" not in out


def test_detection_capacity_is_guided_in_cli(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(runners, "detect_languages", lambda root: {
        "schema_version": runners.PROTOCOL, "status": "UNKNOWN", "languages": {},
        "capacity_reached": True, "execution_performed": False})
    assert main(["runner", "detect", str(tmp_path), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    _assert_guided(report)
    assert "file bound" in report["reason"]
    assert "subdirectory" in report["next_action"]
