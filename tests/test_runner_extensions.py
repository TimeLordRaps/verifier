"""Regression checks for optional native-language and sandbox extension contracts."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from verifier.runtime import language_runners as runners
from verifier.runtime.public_cli import main


def test_openshell_requires_explicit_config_without_local_fallback(tmp_path, capsys) -> None:
    (tmp_path / "main.py").write_text("raise RuntimeError('do not launch')", encoding="utf-8")
    assert main(["runner", "run", "main.py", "--root", str(tmp_path), "--sandbox", "openshell", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert "RUNNER_SANDBOX_CONFIG_REQUIRED" in report["blockers"]
    assert not report["execution_performed"]


def test_catalog_distinguishes_packaged_adapters_from_qualified_runners(capsys) -> None:
    assert main(["runner", "catalog", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    native = [r for r in report["languages"] if r["runner_status"] == "EXTENSION_AVAILABLE"]
    assert {r["language"] for r in native} == {
        "ada", "assembly", "c", "cobol", "cpp", "csharp", "fortran", "go", "java",
        "javascript", "julia", "lisp", "matlab", "object-pascal", "objective-c", "perl",
        "php", "prolog", "r", "rust", "sas", "scratch", "sql", "swift", "visual-basic",
    }
    assert all(r["qualification"] == "NOT_ESTABLISHED" for r in native)


def test_blocker_vocabulary_covers_every_runner_code_literal() -> None:
    # Drift guard: a new RUNNER_* literal in core or an extension package must be
    # added to the closed vocabulary, or it is reported only as a generic code.
    sources = [Path(runners.__file__), *(Path(__file__).resolve().parents[1] / "extensions").rglob("*.py")]
    literals: set[str] = set()
    for path in sources:
        literals |= set(re.findall(r"RUNNER_[A-Z][A-Z0-9_]*", path.read_text(encoding="utf-8")))
    # The toolchain code is a prefix; its tool token is validated at runtime.
    assert literals - {"RUNNER_TOOLCHAIN_MISSING"} <= runners._BLOCKER_CODES


def test_basic_path_does_not_import_or_require_openshell_env(tmp_path) -> None:
    (tmp_path / "main.py").write_text("print('basic')", encoding="utf-8")
    source = Path(__file__).resolve().parents[1] / "src"
    script = """import contextlib,io,json,pathlib,sys
sys.path.insert(0, sys.argv[1])
import verifier
from verifier.runtime.public_cli import main
assert pathlib.Path(verifier.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
out=io.StringIO()
with contextlib.redirect_stdout(out):
    code=main(['runner','run','main.py','--root',sys.argv[2],'--trusted-local','--json'])
report=json.loads(out.getvalue())
assert code == 0 and report['status'] == 'PASS'
assert not any(name.startswith('vstd_openshell') for name in sys.modules)
assert 'environment' not in report and 'environment' not in report['receipt']
"""
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, str(source), str(tmp_path)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("language", "entry", "tool"),
    [
        ("cobol", "subject.cob", "cobc"),
        ("object-pascal", "subject.pas", "fpc"),
        ("ada", "subject.adb", "gnatmake"),
        ("objective-c", "subject.m", "clang"),
        ("assembly", "subject.s", "gcc"),
        ("visual-basic", "subject.vb", "dotnet"),
        ("scratch", "subject.sb3", "scratch-vm-headless"),
        ("matlab", "subject.m", "matlab"),
        ("sas", "subject.sas", "sas"),
    ],
)
def test_new_ranked_adapters_reach_optional_openshell_without_host_tool_lookup(
    tmp_path, capsys, monkeypatch, language, entry, tool
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "extensions/languages/src"))
    (tmp_path / entry).write_bytes(b"source bytes")
    config = tmp_path / "sandbox.json"
    config.write_text("{}", encoding="utf-8")
    calls: list[dict] = []

    class Backend:
        name = "openshell"

        def load(self):
            def run(request):
                calls.append(request)
                return {
                    "schema_version": "verifier-openshell-result-1",
                    "status": "UNKNOWN",
                    "execution_performed": False,
                    "sandbox_status": "NOT_ESTABLISHED",
                    "blockers": ["RUNNER_OPENSHELL_EXECUTION_INCOMPLETE"],
                }

            return run

    monkeypatch.setattr(runners, "_sandbox_extensions", lambda: [Backend()])
    assert main([
        "runner", "run", entry, "--root", str(tmp_path), "--language", language,
        "--sandbox", "openshell", "--sandbox-config", str(config), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["extension_status"] == "LOADED"
    assert report["execution_attempted"] is True
    assert report["execution_performed"] is False
    assert report["status"] == "UNKNOWN"
    assert len(calls) == 1
    request = calls[0]
    assert request["argv"][:4] == ["python3", "-I", "-B", "-c"]
    offset = 6 if language in {"visual-basic", "scratch", "matlab", "sas"} else 5
    assert request["argv"][offset:offset + 3] == [language, tool, "/sandbox/source/" + entry]
    assert max(map(len, request["argv"])) <= 8192
    assert request["root"] == str(tmp_path.resolve())
    assert request["entry"] == entry
    assert request["profile"]["qualification"] == "NOT_ESTABLISHED"
