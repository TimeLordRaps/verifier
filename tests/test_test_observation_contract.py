"""Require bounded, visible test execution in hosted verification workflows."""

from __future__ import annotations

from pathlib import Path
import shlex

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("workflow_name", ("ci.yml", "release.yml"))
def test_hosted_pytest_commands_are_streaming_and_bounded(workflow_name: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
    )
    commands = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            for line in str(step.get("run", "")).splitlines():
                if "-m pytest " not in line:
                    continue
                command = shlex.split(line)
                commands.append(command)
                assert command[:2] == ["python", "-u"], command
                assert "-vv" in command, command
                assert "-s" in command, command
                assert "--durations=10" in command, command
                assert "--timeout=60" in command, command
                assert not {"-q", "-qq", "--quiet"}.intersection(command), command
                assert 0 < job["timeout-minutes"] <= 60
    assert commands, workflow_name


def test_timeout_plugin_is_an_explicit_test_dependency() -> None:
    assert '"pytest-timeout==2.4.0"' in (ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )
