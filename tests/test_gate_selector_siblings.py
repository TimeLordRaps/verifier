"""Independent text-scope controls for source files and retained archive members."""
from __future__ import annotations

import io
from pathlib import Path
import tarfile
import zipfile

import pytest

from verifier.runtime import gate


NAMES = ["client.js", "view.jsx", "client.ts", "view.tsx", "module.mjs",
         "module.cjs", "module.mts", "module.cts", "tool.ps1", "tool.psm1",
         "tool.psd1", "launch.bat", "launch.cmd", "paper.tex", "data.json5",
         "data.jsonc", "Dockerfile", "Makefile", "LICENSE", "NOTICE", "AUTHORS", "COPYING"]


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("uppercase", [False, True])
def test_selected_file_case_variants_detect_actual_paths(tmp_path: Path, name: str, uppercase: bool) -> None:
    filename = name.upper() if uppercase else name
    (tmp_path / "clean.md").write_text("relative/file", encoding="utf-8")
    (tmp_path / filename).write_text("E:" + "/synthetic-workspace/data", encoding="utf-8")
    count, findings = gate.run_paths_gate(tmp_path)
    assert count == 2
    assert len(findings) == 1 and findings[0]["label"] == "Windows drive path"


@pytest.mark.parametrize("name", NAMES)
def test_portable_selected_file_is_actually_scanned(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_text("relative/file", encoding="utf-8")
    assert gate.run_paths_gate(path) == (1, [])


@pytest.mark.parametrize("member", ["source/client.ts", "site/view.jsx", "paper.tex", "LICENSE"])
@pytest.mark.parametrize("suffix", [".zip", ".whl", ".tar.gz"])
def test_archive_member_selection_cannot_skip_forbidden_content(tmp_path: Path, member: str, suffix: str) -> None:
    path = tmp_path / ("payload" + suffix)
    records = {"clean.md": b"relative/file", member: b"synthetic-private-marker"}
    if suffix == ".tar.gz":
        with tarfile.open(path, "w:gz") as archive:
            for name, data in records.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    else:
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in records.items():
                archive.writestr(name, data)
    count, findings = gate.run_boundary_gate(path, forbidden_terms=["synthetic-private-marker"])
    assert count == 2
    assert len(findings) == 1 and findings[0]["kind"] == "forbidden_term_leak"
    assert findings[0]["location"].endswith(":" + member)
    assert "synthetic-private-marker" not in str(findings)


@pytest.mark.parametrize("name", ["view.tsx", "LICENSE", "tool.ps1"])
def test_selected_undecodable_text_fails_closed(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_bytes(b"\xff\xfe")
    count, findings = gate.run_paths_gate(path)
    assert count == 0 and len(findings) == 1
    assert findings[0]["kind"] == "incomplete_scan"
    assert findings[0]["label"].startswith("UnicodeDecodeError:")


def test_selected_file_byte_limit_still_prevents_unbounded_read(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gate, "MAX_SCAN_FILE_BYTES", 8)
    path = tmp_path / "client.js"
    path.write_bytes(b"x" * 9)
    count, findings = gate.run_paths_gate(path)
    assert count == 0 and len(findings) == 1
    assert "beyond bounds" in findings[0]["label"]


def test_unknown_extensionless_binary_is_not_selected_as_text(tmp_path: Path) -> None:
    (tmp_path / "clean.md").write_text("relative/file", encoding="utf-8")
    (tmp_path / "executable").write_bytes(b"\x00\xff")
    assert gate.run_paths_gate(tmp_path) == (1, [])


def test_explicit_exclusion_retains_nonempty_clean_scope(tmp_path: Path) -> None:
    (tmp_path / "clean.md").write_text("relative/file", encoding="utf-8")
    (tmp_path / "client.js").write_text("E:" + "/synthetic-workspace/data", encoding="utf-8")
    assert gate.run_paths_gate(tmp_path, additional_excludes=["client.js"]) == (1, [])
