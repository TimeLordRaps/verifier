"""Bounded, streaming test observation in continuous integration (CI)."""

from __future__ import annotations

from pathlib import Path
import shlex

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
FLAGS = {"-vv", "-s", "--durations=10", "--timeout=60"}


@pytest.mark.parametrize("filename", ["ci.yml", "release.yml"])
def test_hosted_tests_stream_names_and_have_finite_timeouts(filename: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
    )
    test_commands = []
    for job_name, job in workflow["jobs"].items():
        timeout = job.get("timeout-minutes")
        assert type(timeout) is int and 1 <= timeout <= 30, job_name
        for step in job["steps"]:
            for line in step.get("run", "").splitlines():
                if "pytest" not in line and "compileall" not in line:
                    continue
                tokens = shlex.split(line)
                if "pytest" in tokens:
                    test_commands.append(tokens)
                    assert tokens[:3] == ["python", "-u", "-m"], line
                    assert FLAGS <= set(tokens), line
                    assert not {"-q", "-qq", "--quiet"} & set(tokens), line
                if "compileall" in tokens:
                    assert "-q" not in tokens, line
    assert test_commands, filename


def test_test_extra_and_release_instructions_support_observation() -> None:
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    test_extra = next(line for line in metadata.splitlines() if line.startswith("test = "))
    assert '"pytest-timeout==2.4.0"' in test_extra
    instructions = (ROOT / "RELEASING.md").read_text(encoding="utf-8")
    assert "python -u -m pytest -vv -s --durations=10 --timeout=60" in instructions


def test_every_repository_check_pytest_invocation_retains_skip_evidence() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    observed_jobs = set()
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            for line in step.get("run", "").splitlines():
                if "pytest" not in line:
                    continue
                tokens = shlex.split(line)
                observed_jobs.add(job_name)
                assert "-p" in tokens, (job_name, line)
                plugin_index = tokens.index("-p")
                assert tokens[plugin_index + 1] == "scripts.pytest_public_evidence", (
                    job_name,
                    line,
                )
                assert sum(token.startswith("--junitxml=") for token in tokens) == 1, (
                    job_name,
                    line,
                )
    assert observed_jobs == {
        "artifact-seal",
        "base",
        "coverage",
        "platform-python-contracts",
        "scitt-crypto",
    }


@pytest.mark.parametrize("filename", ["AGENTS.md", "CONTRIBUTING.md"])
def test_contributor_instructions_never_prescribe_quiet_unbounded_tests(
    filename: str,
) -> None:
    instructions = (ROOT / filename).read_text(encoding="utf-8")
    for line in instructions.splitlines():
        if "pytest" in line and line.lstrip().startswith("python"):
            tokens = shlex.split(line)
            assert FLAGS <= set(tokens), line
            assert not {"-q", "-qq", "--quiet"} & set(tokens), line
        if "compileall" in line and line.lstrip().startswith("python"):
            assert "-q" not in shlex.split(line), line


@pytest.mark.parametrize(
    "filename", ["ci.yml", "release.yml", "pages.yml", "external-links.yml", "pr-policy.yml"]
)
def test_every_hosted_job_has_a_finite_timeout(filename: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
    )
    for job_name, job in workflow["jobs"].items():
        timeout = job.get("timeout-minutes")
        assert type(timeout) is int and 1 <= timeout <= 30, (filename, job_name)
