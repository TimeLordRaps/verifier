"""Hostile Git environment/config regressions for the estate observer."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from verifier.runtime import self_polish_estate as estate


def _require_git() -> None:
    if shutil.which("git") is None:
        pytest.skip(
            "OPTIONAL_DEPENDENCY_ABSENT: git executable is unavailable on PATH "
            "for observer isolation"
        )


def _fixture_environment() -> dict[str, str]:
    """Keep fixture construction independent of caller Git redirectors."""

    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=_fixture_environment(),
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout


def _repository(root: Path, content: str) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    (root / "tracked.txt").write_text(content, encoding="utf-8")
    _git(root, "add", "tracked.txt")
    _git(
        root,
        "-c", "user.name=Verifier fixture",
        "-c", "user.email=fixture" "@example.invalid",
        "commit", "-q", "-m", "initial",
    )
    _git(
        root, "remote", "add", "origin",
        "https://example.invalid/observer-fixture.git",
    )
    return root


def test_git_coordinate_ignores_ambient_repository_redirectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_git()
    selected = _repository(tmp_path / "selected", "selected\n")
    other = _repository(tmp_path / "other", "other\n")
    selected_head = _git(selected, "rev-parse", "HEAD").decode().strip()
    assert selected_head != _git(other, "rev-parse", "HEAD").decode().strip()

    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_INDEX_FILE", str(other / ".git" / "index"))

    assert estate._git_coordinate(selected)["revision"] == selected_head
    assert estate._git_tracked_paths(selected) == ("tracked.txt",)


def test_git_observer_disables_repository_fsmonitor_side_effects(
    tmp_path: Path,
) -> None:
    _require_git()
    selected = _repository(tmp_path / "selected", "selected\n")
    marker = tmp_path / "fsmonitor-fired.txt"
    monitor = tmp_path / "fsmonitor.py"
    monitor.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('fired', encoding='utf-8')\n",
        encoding="utf-8",
    )
    command = f'"{Path(sys.executable).as_posix()}" "{monitor.as_posix()}"'
    _git(selected, "config", "core.fsmonitor", command)

    estate._git_status_digest(selected)
    estate._git_untracked_paths(selected)

    assert not marker.exists()


@pytest.mark.parametrize(
    "source",
    ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT"),
)
def test_git_untracked_paths_ignore_ambient_config_sources(
    source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_git()
    selected = _repository(tmp_path / "selected", "selected\n")
    hidden = selected / "ambient-hidden.txt"
    hidden.write_text("must remain visible\n", encoding="utf-8")
    excludes = tmp_path / "ambient-excludes"
    excludes.write_text("ambient-hidden.txt\n", encoding="utf-8")
    config = tmp_path / "ambient.gitconfig"
    config.write_text(
        "[core]\n\texcludesFile = " + excludes.as_posix() + "\n",
        encoding="utf-8",
    )

    if source == "GIT_CONFIG_COUNT":
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", excludes.as_posix())
    else:
        monkeypatch.setenv(source, str(config))

    assert "ambient-hidden.txt" in estate._git_untracked_paths(selected)


def test_git_launch_uses_closed_environment_absolute_argv_and_no_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_git()
    selected = tmp_path.resolve()
    monkeypatch.setenv("GIT_DIR", "hostile")
    observed = {}

    def run(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout=b"ok")

    monkeypatch.setattr(estate.subprocess, "run", run)
    assert estate._run_git(selected, "rev-parse", "HEAD") == b"ok"

    argv = observed["argv"]
    kwargs = observed["kwargs"]
    assert Path(argv[0]).is_absolute()
    assert kwargs.get("shell", False) is False
    assert kwargs["cwd"] == selected
    assert not any(key.upper() == "GIT_DIR" for key in kwargs["env"])
    assert kwargs["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
