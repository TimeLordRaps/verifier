from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_R2_SCRIPTS = {
    "scripts/build_component_index.py",
    "scripts/build_self_polish_tier1_ledger.py",
    "scripts/check_pr_description.py",
    "scripts/check_prdel_v2_selection.py",
    "scripts/check_prdel_v2_selection_r2.py",
}


def test_test_extra_pins_sdist_build_frontend() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    optional_dependencies = pyproject.split(
        "[project.optional-dependencies]", 1
    )[1].split("\n[", 1)[0]
    test_array = re.search(
        r"(?ms)^test\s*=\s*\[(?P<values>.*?)\]",
        optional_dependencies,
    )
    assert test_array is not None
    test_dependencies = set(re.findall(r'"([^"]+)"', test_array.group("values")))
    assert "build==1.5.0" in test_dependencies


def test_sdist_contains_exact_r2_reconstruction_scripts(tmp_path: Path) -> None:
    source_copy = tmp_path / "source"
    shutil.copytree(
        ROOT,
        source_copy,
        ignore=shutil.ignore_patterns(
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            ".venv",
            "*.egg-info",
            "__pycache__",
            "artifacts_tmp",
            "build",
            "dist",
        ),
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--outdir",
            "dist-output",
            ".",
        ],
        cwd=source_copy,
        check=True,
        capture_output=True,
        text=True,
    )

    archives = list((source_copy / "dist-output").glob("*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0], "r:gz") as archive:
        relative_files = {
            name.split("/", 1)[1]
            for member in archive.getmembers()
            if member.isfile()
            and "/" in (name := member.name.replace("\\", "/"))
        }

    packaged_scripts = {
        name for name in relative_files if name.startswith("scripts/")
    }
    assert packaged_scripts == REQUIRED_R2_SCRIPTS
