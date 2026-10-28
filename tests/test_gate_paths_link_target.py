"""The public command-line interface (CLI) must retain linked-root rejection."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from verifier.runtime import gate
from verifier.runtime.public_cli import main


@pytest.mark.parametrize("json_output", [False, True])
def test_paths_cli_rejects_linked_root_without_following_it(tmp_path: Path, capsys: pytest.CaptureFixture[str], json_output: bool) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "clean.js").write_text("docs/guide.md", encoding="utf-8")
    linked = tmp_path / "linked"
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            pytest.skip("OS_CAPABILITY_GUARD: Windows system directory is unavailable")
        powershell = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():
            pytest.skip("OS_CAPABILITY_GUARD: Windows junction creation tool is unavailable")
        def quote(value: Path) -> str:
            return "'" + str(value).replace("'", "''") + "'"
        command = "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path " + quote(linked) + " -Target " + quote(real) + " | Out-Null"
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, "Local fixture junction creation failed"
    else:
        try:
            linked.symlink_to(real, target_is_directory=True)
        except OSError:
            pytest.skip("OS_CAPABILITY_GUARD: directory symlink creation is unavailable")
    assert gate._link_like(linked), "The fixture must be an actual linked entry"
    count, findings = gate.run_paths_gate(linked)
    assert count == 0 and findings and findings[0]["kind"] == "incomplete_scan"
    args = ["--json"] if json_output else []
    assert main(["gate", "paths", str(real), *args]) == 0
    clean_output = capsys.readouterr().out
    assert "PASS" in clean_output
    assert main(["gate", "paths", str(linked), *args]) == 1
    output = capsys.readouterr().out
    assert "FAIL" in output
    assert str(tmp_path) not in output and tmp_path.as_posix() not in output
    if json_output:
        record = json.loads(output)
        assert record["scanned_files"] == 0 and record["violations"]
