"""Bounded, streaming test observation in continuous integration (CI)."""

from __future__ import annotations

from pathlib import Path
import shlex

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
FLAGS = {"-vv", "-s", "--durations=10", "--timeout=60"}


def _test_commands(script: str) -> list[tuple[str, list[str]]]:
    """Inspect literal workflow commands, joining their shell continuations.

    This is not a general shell interpreter. Dependency installation is not a
    test invocation; direct module launches and coverage's nested module are.
    """
    commands = []
    for line in script.replace("\\\n", "").splitlines():
        if "pytest" not in line and "compileall" not in line:
            continue
        tokens = shlex.split(line, comments=True)
        if not tokens:
            continue
        installation = (
            tokens[:4] == ["python", "-m", "pip", "install"]
            or tokens[:5] == ["python", "-u", "-m", "pip", "install"]
        ) and not any(character in token for token in tokens for character in ";|&")
        for module in ("pytest", "compileall"):
            if module in tokens and not installation:
                commands.append((module, tokens))
    return commands


def _assert_pytest_observation(tokens: list[str]) -> None:
    assert tokens[:3] == ["python", "-u", "-m"], tokens
    assert FLAGS <= set(tokens), tokens
    assert not {"-q", "-qq", "--quiet"} & set(tokens), tokens


def _assert_skip_evidence(tokens: list[str]) -> None:
    plugins = [value for flag, value in zip(tokens, tokens[1:]) if flag == "-p"]
    assert plugins.count("scripts.pytest_public_evidence") == 1, tokens
    assert sum(token.startswith("--junitxml=") for token in tokens) == 1, tokens


def test_observation_recognizes_continued_execution_not_dependency_installation() -> None:
    script = (
        "python -m pip install 'pytest>=8.0' pytest-timeout==2.4.0\n"
        "python -m pip install pytest\n"
        "# python -m pytest is discussed, not executed here\n"
        "python -u -m pytest tests/installed_composition_workflow.py \\\n"
        "  -p pytest_timeout -p scripts.pytest_public_evidence \\\n"
        "  -vv -s --durations=10 --timeout=60 --junitxml=installed.xml\n"
    )
    commands = _test_commands(script)
    assert len(commands) == 1
    module, tokens = commands[0]
    assert module == "pytest"
    _assert_pytest_observation(tokens)
    _assert_skip_evidence(tokens)


@pytest.mark.parametrize("launcher", ["python -m pytest", "pytest", "uv run pytest", "python -u -m coverage run -m pytest", "python -m pip install pytest && pytest"])
def test_observation_still_detects_direct_and_coverage_launches(launcher: str) -> None:
    commands = _test_commands(launcher)
    assert len(commands) == 1 and commands[0][0] == "pytest"
    with pytest.raises(AssertionError):
        _assert_pytest_observation(commands[0][1])


@pytest.mark.parametrize("removed", sorted(FLAGS | {"-u"}))
def test_observation_still_rejects_missing_streaming_or_timeout_flags(removed: str) -> None:
    tokens = ["python", "-u", "-m", "pytest", *sorted(FLAGS)]
    tokens.remove(removed)
    with pytest.raises(AssertionError):
        _assert_pytest_observation(tokens)


@pytest.mark.parametrize("quiet", ["-q", "-qq", "--quiet"])
def test_observation_still_rejects_quiet_flags(quiet: str) -> None:
    with pytest.raises(AssertionError):
        _assert_pytest_observation(["python", "-u", "-m", "pytest", *sorted(FLAGS), quiet])


def test_observation_does_not_hide_a_truncated_continuation() -> None:
    with pytest.raises(ValueError):
        _test_commands("python -u -m pytest \\")


@pytest.mark.parametrize("plugins", [[], ["-p", "pytest_timeout"], ["-p", "scripts.pytest_public_evidence"] * 2])
def test_skip_evidence_requires_exactly_one_public_evidence_plugin(plugins: list[str]) -> None:
    with pytest.raises(AssertionError):
        _assert_skip_evidence(["python", "-u", "-m", "pytest", *plugins, "--junitxml=tests.xml"])


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
            for module, tokens in _test_commands(step.get("run", "")):
                if module == "pytest":
                    test_commands.append(tokens)
                    _assert_pytest_observation(tokens)
                if module == "compileall":
                    assert "-q" not in tokens, tokens
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
            for module, tokens in _test_commands(step.get("run", "")):
                if module != "pytest":
                    continue
                observed_jobs.add(job_name)
                _assert_skip_evidence(tokens)
    assert observed_jobs == {
        "artifact-seal",
        "base",
        "coverage",
        "installed-wheel-smoke",
        "logits-constraints",
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


WORKFLOWS = sorted(path.name for path in (ROOT / ".github" / "workflows").glob("*.yml"))


def test_the_workflow_list_is_discovered_not_written_down() -> None:
    assert "ci.yml" in WORKFLOWS and "pr-description.yml" in WORKFLOWS


@pytest.mark.parametrize("filename", WORKFLOWS)
def test_every_hosted_job_has_a_finite_timeout(filename: str) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
    )
    for job_name, job in workflow["jobs"].items():
        timeout = job.get("timeout-minutes")
        assert type(timeout) is int and 1 <= timeout <= 30, (filename, job_name)
